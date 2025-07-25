package runner

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/clistats"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"github.com/projectdiscovery/goconfig"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/hmap/store/hybrid"
	"github.com/projectdiscovery/mapcidr"
	"github.com/projectdiscovery/mapcidr/asn"
	"github.com/projectdiscovery/ratelimit"
	"github.com/projectdiscovery/retryabledns"
	fileutil "github.com/projectdiscovery/utils/file"
	iputil "github.com/projectdiscovery/utils/ip"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
)

// Runner is a client for running the enumeration process.
type Runner struct {
	options             *Options
	dnsx                *dnsx.DNSX
	wgoutputworker      *sync.WaitGroup
	wgresolveworkers    *sync.WaitGroup
	wgwildcardworker    *sync.WaitGroup
	workerchan          chan string
	outputchan          chan string
	wildcardworkerchan  chan string
	wildcards           *mapsutil.SyncLockMap[string, struct{}]
	wildcardscache      map[string][]string
	wildcardscachemutex sync.Mutex
	limiter             *ratelimit.Limiter
	hm                  *hybrid.HybridMap
	stats               clistats.StatisticsClient
	tmpStdinFile        string
	aurora              aurora.Aurora
}

func New(options *Options) (*Runner, error) {
	retryabledns.CheckInternalIPs = true

	dnsxOptions := dnsx.DefaultOptions
	dnsxOptions.MaxRetries = options.Retries
	dnsxOptions.TraceMaxRecursion = options.TraceMaxRecursion
	dnsxOptions.Hostsfile = options.HostsFile
	dnsxOptions.OutputCDN = options.OutputCDN
	dnsxOptions.Proxy = options.Proxy
	if options.Resolvers != "" {
		dnsxOptions.BaseResolvers = []string{}
		// If it's a file load resolvers from it
		if fileutil.FileExists(options.Resolvers) {
			rs, err := linesInFile(options.Resolvers)
			if err != nil {
				gologger.Fatal().Msgf("%s\n", err)
			}
			for _, rr := range rs {
				dnsxOptions.BaseResolvers = append(dnsxOptions.BaseResolvers, prepareResolver(rr))
			}
		} else {
			// otherwise gets comma separated ones
			for _, rr := range strings.Split(options.Resolvers, ",") {
				dnsxOptions.BaseResolvers = append(dnsxOptions.BaseResolvers, prepareResolver(rr))
			}
		}
	}

	var questionTypes []uint16
	if options.A {
		questionTypes = append(questionTypes, dns.TypeA)
	}
	if options.AAAA {
		questionTypes = append(questionTypes, dns.TypeAAAA)
	}
	if options.CNAME {
		questionTypes = append(questionTypes, dns.TypeCNAME)
	}
	if options.PTR {
		questionTypes = append(questionTypes, dns.TypePTR)
	}
	if options.SOA {
		questionTypes = append(questionTypes, dns.TypeSOA)
	}
	if options.ANY {
		questionTypes = append(questionTypes, dns.TypeANY)
	}
	if options.TXT {
		questionTypes = append(questionTypes, dns.TypeTXT)
	}
	if options.SRV {
		questionTypes = append(questionTypes, dns.TypeSRV)
	}
	if options.MX {
		questionTypes = append(questionTypes, dns.TypeMX)
	}
	if options.NS {
		questionTypes = append(questionTypes, dns.TypeNS)
	}
	if options.CAA {
		questionTypes = append(questionTypes, dns.TypeCAA)
	}

	// If no option is specified or wildcard filter has been requested use query type A
	if len(questionTypes) == 0 || options.WildcardDomain != "" {
		options.A = true
		questionTypes = append(questionTypes, dns.TypeA)
	}
	dnsxOptions.QuestionTypes = questionTypes
	dnsxOptions.QueryAll = options.QueryAll

	dnsX, err := dnsx.New(dnsxOptions)
	if err != nil {
		return nil, err
	}

	limiter := ratelimit.NewUnlimited(context.Background())
	if options.RateLimit > 0 {
		limiter = ratelimit.New(context.Background(), uint(options.RateLimit), time.Second)
	}

	hm, err := hybrid.New(hybrid.DefaultDiskOptions)
	if err != nil {
		return nil, err
	}

	var stats clistats.StatisticsClient
	if options.ShowStatistics {
		stats, err = clistats.New()
		if err != nil {
			return nil, err
		}
	}

	if os.Getenv("NO_COLOR") == "true" {
		options.NoColor = true
	}

	r := Runner{
		options:            options,
		dnsx:               dnsX,
		wgoutputworker:     &sync.WaitGroup{},
		wgresolveworkers:   &sync.WaitGroup{},
		wgwildcardworker:   &sync.WaitGroup{},
		workerchan:         make(chan string),
		wildcardworkerchan: make(chan string),
		wildcards:          mapsutil.NewSyncLockMap[string, struct{}](),
		wildcardscache:     make(map[string][]string),
		limiter:            limiter,
		hm:                 hm,
		stats:              stats,
		aurora:             aurora.NewAurora(!options.NoColor),
	}

	return &r, nil
}

func (r *Runner) InputWorkerStream() {
	var sc *bufio.Scanner
	// attempt to load list from file
	if fileutil.FileExists(r.options.Hosts) {
		f, _ := os.Open(r.options.Hosts)
		sc = bufio.NewScanner(f)
	} else if fileutil.HasStdin() {
		sc = bufio.NewScanner(os.Stdin)
	}

	for sc.Scan() {
		item := strings.TrimSpace(sc.Text())
		switch {
		case iputil.IsCIDR(item):
			hostsC, _ := mapcidr.IPAddressesAsStream(item)
			for host := range hostsC {
				r.workerchan <- host
			}
		case asn.IsASN(item):
			hostsC, _ := asn.GetIPAddressesAsStream(item)
			for host := range hostsC {
				r.workerchan <- host
			}
		default:
			r.workerchan <- item
		}
	}
	close(r.workerchan)
}

func (r *Runner) InputWorker() {
	r.hm.Scan(func(k, _ []byte) error {
		if r.options.ShowStatistics {
			r.stats.IncrementCounter("requests", len(r.dnsx.Options.QuestionTypes))
		}
		item := string(k)
		if r.options.resumeCfg != nil {
			r.options.resumeCfg.current = item
			r.options.resumeCfg.currentIndex++
			if r.options.resumeCfg.currentIndex <= r.options.resumeCfg.Index {
				return nil
			}
		}
		r.workerchan <- item
		return nil
	})
	close(r.workerchan)
}

func (r *Runner) prepareInput() error {
	var (
		dataDomains chan string
		sc          chan string
		err         error
	)

	// copy stdin to a temporary file
	hasStdin := fileutil.HasStdin()
	if hasStdin {
		tmpStdinFile, err := fileutil.GetTempFileName()
		if err != nil {
			return err
		}
		r.tmpStdinFile = tmpStdinFile

		stdinFile, err := os.Create(r.tmpStdinFile)
		if err != nil {
			return err
		}
		if _, err := io.Copy(stdinFile, os.Stdin); err != nil {
			return err
		}
		// closes the file as we will read it multiple times to build the iterations
		stdinFile.Close()
		defer os.RemoveAll(r.tmpStdinFile)
	}

	if r.options.Domains != "" {
		dataDomains, err = r.preProcessArgument(r.options.Domains)
		if err != nil {
			return err
		}
		sc = dataDomains
	}

	if sc == nil {
		// attempt to load list from file
		if fileutil.FileExists(r.options.Hosts) {
			f, err := fileutil.ReadFile(r.options.Hosts)
			if err != nil {
				return err
			}
			sc = f
		} else if argumentHasStdin(r.options.Hosts) || hasStdin {
			sc, err = fileutil.ReadFile(r.tmpStdinFile)
			if err != nil {
				return err
			}
		} else {
			return errors.New("hosts file or stdin not provided")
		}
	}

	numHosts := 0
	for item := range sc {
		item := normalize(item)
		var hosts []string
		switch {
		case strings.Contains(item, "FUZZ"):
			fuzz, err := r.preProcessArgument(r.options.WordList)
			if err != nil {
				return err
			}
			for r := range fuzz {
				subdomain := strings.ReplaceAll(item, "FUZZ", r)
				hosts = append(hosts, subdomain)
			}
			numHosts += r.addHostsToHMapFromList(hosts)
		case r.options.WordList != "":
			// prepare wordlist
			prefixes, err := r.preProcessArgument(r.options.WordList)
			if err != nil {
				return err
			}
			for prefix := range prefixes {
				// domains Cartesian product with wordlist
				subdomain := strings.TrimSpace(prefix) + "." + item
				hosts = append(hosts, subdomain)
			}
			numHosts += r.addHostsToHMapFromList(hosts)
		case iputil.IsCIDR(item):
			hostC, err := mapcidr.IPAddressesAsStream(item)
			if err != nil {
				return err
			}
			numHosts += r.addHostsToHMapFromChan(hostC)
		case asn.IsASN(item):
			hostC, err := asn.GetIPAddressesAsStream(item)
			if err != nil {
				return err
			}
			numHosts += r.addHostsToHMapFromChan(hostC)
		default:
			hosts = []string{item}
			numHosts += r.addHostsToHMapFromList(hosts)
		}
	}
	if r.options.ShowStatistics {
		r.stats.AddStatic("hosts", numHosts)
		r.stats.AddStatic("startedAt", time.Now())
		r.stats.AddCounter("requests", 0)
		r.stats.AddCounter("total", uint64(numHosts*len(r.dnsx.Options.QuestionTypes)))
		r.stats.AddDynamic("summary", makePrintCallback())
		// nolint:errcheck
		r.stats.Start()
		r.stats.GetStatResponse(time.Second*5, func(s string, err error) error {
			if err != nil && r.options.Verbose {
				gologger.Error().Msgf("Could not read statistics: %s\n", err)
			}
			return nil
		})
	}
	return nil
}

func (r *Runner) addHostsToHMapFromList(hosts []string) (numHosts int) {
	for _, host := range hosts {
		// Used just to get the exact number of targets
		if _, ok := r.hm.Get(host); ok {
			continue
		}
		numHosts++
		// nolint:errcheck
		r.hm.Set(host, nil)
	}
	return
}

func (r *Runner) addHostsToHMapFromChan(hosts chan string) (numHosts int) {
	for host := range hosts {
		// Used just to get the exact number of targets
		if _, ok := r.hm.Get(host); ok {
			continue
		}
		numHosts++
		// nolint:errcheck
		r.hm.Set(host, nil)
	}
	return
}

func (r *Runner) preProcessArgument(arg string) (chan string, error) {
	// read from:
	// file
	switch {
	case fileutil.FileExists(arg):
		return fileutil.ReadFile(arg)
	// stdin
	case argumentHasStdin(arg):
		return fileutil.ReadFile(r.tmpStdinFile)
	// inline
	case arg != "":
		data := strings.ReplaceAll(arg, Comma, NewLine)
		return fileutil.ReadFileWithReader(strings.NewReader(data))
	default:
		return nil, errors.New("empty argument")
	}
}

func normalize(data string) string {
	return strings.TrimSpace(data)
}

// nolint:deadcode
func makePrintCallback() func(stats clistats.StatisticsClient) interface{} {
	builder := &strings.Builder{}
	return func(stats clistats.StatisticsClient) interface{} {
		builder.WriteRune('[')
		startedAt, _ := stats.GetStatic("startedAt")
		duration := time.Since(startedAt.(time.Time))
		builder.WriteString(fmtDuration(duration))
		builder.WriteRune(']')

		hosts, _ := stats.GetStatic("hosts")
		builder.WriteString(" | Hosts: ")
		builder.WriteString(clistats.String(hosts))

		requests, _ := stats.GetCounter("requests")
		total, _ := stats.GetCounter("total")

		builder.WriteString(" | RPS: ")
		builder.WriteString(clistats.String(uint64(float64(requests) / duration.Seconds())))

		builder.WriteString(" | Requests: ")
		builder.WriteString(clistats.String(requests))
		builder.WriteRune('/')
		builder.WriteString(clistats.String(total))
		builder.WriteRune(' ')
		builder.WriteRune('(')
		//nolint:gomnd // this is not a magic number
		builder.WriteString(clistats.String(uint64(float64(requests) / float64(total) * 100.0)))
		builder.WriteRune('%')
		builder.WriteRune(')')
		builder.WriteRune('\n')

		fmt.Fprintf(os.Stderr, "%s", builder.String())
		statString := builder.String()
		builder.Reset()
		return statString
	}
}

// SaveResumeConfig to file
func (r *Runner) SaveResumeConfig() error {
	var resumeCfg ResumeCfg
	resumeCfg.Index = r.options.resumeCfg.currentIndex
	resumeCfg.ResumeFrom = r.options.resumeCfg.current
	return goconfig.Save(resumeCfg, DefaultResumeFile)
}

func (r *Runner) Run() error {
	if r.options.Stream {
		return r.runStream()
	}

	return r.run()
}

func (r *Runner) run() error {
	err := r.prepareInput()
	if err != nil {
		return err
	}

	// if resume is enabled inform the user
	if r.options.ShouldLoadResume() && r.options.resumeCfg.Index > 0 {
		gologger.Debug().Msgf("Resuming scan using file %s. Restarting at position %d: %s\n", DefaultResumeFile, r.options.resumeCfg.Index, r.options.resumeCfg.ResumeFrom)
	}

	r.startWorkers()

	r.wgresolveworkers.Wait()
	if r.stats != nil {
		err = r.stats.Stop()
		if err != nil {
			return err
		}
	}

	close(r.outputchan)
	r.wgoutputworker.Wait()

	if r.options.WildcardDomain != "" {
		gologger.Print().Msgf("Starting to filter wildcard subdomains\n")
		ipDomain := make(map[string]map[string]struct{})
		listIPs := []string{}
		// prepare in memory structure similarly to shuffledns
		r.hm.Scan(func(k, v []byte) error {
			var dnsdata retryabledns.DNSData
			if err := json.Unmarshal(v, &dnsdata); err != nil {
				// the item has no record - ignore
				return nil
			}

			for _, a := range dnsdata.A {
				_, ok := ipDomain[a]
				if !ok {
					ipDomain[a] = make(map[string]struct{})
					listIPs = append(listIPs, a)
				}
				ipDomain[a][string(k)] = struct{}{}
			}

			return nil
		})

		gologger.Debug().Msgf("Found %d unique IPs:%s\n", len(listIPs), strings.Join(listIPs, ", "))
		// wildcard workers
		numThreads := r.options.Threads
		if numThreads > len(listIPs) {
			numThreads = len(listIPs)
		}
		for i := 0; i < numThreads; i++ {
			r.wgwildcardworker.Add(1)
			go r.wildcardWorker()
		}

		seen := make(map[string]struct{})
		for _, a := range listIPs {
			hosts := ipDomain[a]
			if len(hosts) >= r.options.WildcardThreshold {
				for host := range hosts {
					if _, ok := seen[host]; !ok {
						seen[host] = struct{}{}
						r.wildcardworkerchan <- host
					}
				}
			}
		}
		close(r.wildcardworkerchan)
		r.wgwildcardworker.Wait()

		// we need to restart output
		r.startOutputWorker()
		seen = make(map[string]struct{})
		seenRemovedSubdomains := make(map[string]struct{})
		numRemovedSubdomains := 0
		for _, A := range listIPs {
			for host := range ipDomain[A] {
				if host == r.options.WildcardDomain {
					if _, ok := seen[host]; !ok {
						seen[host] = struct{}{}
						_ = r.lookupAndOutput(host)
					}
				} else if !r.wildcards.Has(host) {
					if _, ok := seen[host]; !ok {
						seen[host] = struct{}{}
						_ = r.lookupAndOutput(host)
					}
				} else {
					if _, ok := seenRemovedSubdomains[host]; !ok {
						numRemovedSubdomains++
						seenRemovedSubdomains[host] = struct{}{}
					}
				}
			}
		}
		close(r.outputchan)
		// waiting output worker
		r.wgoutputworker.Wait()
		gologger.Print().Msgf("%d wildcard subdomains removed\n", numRemovedSubdomains)
	}

	return nil
}

func (r *Runner) lookupAndOutput(host string) error {
	if r.options.JSON {
		if data, ok := r.hm.Get(host); ok {
			var dnsData retryabledns.DNSData
			err := dnsData.Unmarshal(data)
			if err != nil {
				return err
			}
			dnsDataJson, err := dnsData.JSON()
			if err != nil {
				return err
			}
			r.outputchan <- dnsDataJson
			return err
		}
	}

	r.outputchan <- host
	return nil
}

func (r *Runner) runStream() error {
	r.startWorkers()

	r.wgresolveworkers.Wait()

	close(r.outputchan)
	r.wgoutputworker.Wait()

	return nil
}

func (r *Runner) HandleOutput() {
	defer r.wgoutputworker.Done()

	// setup output
	var (
		foutput *os.File
		w       *bufio.Writer
	)
	if r.options.OutputFile != "" {
		var err error
		foutput, err = os.OpenFile(r.options.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			gologger.Fatal().Msgf("%s\n", err)
		}
		defer foutput.Close()
		w = bufio.NewWriter(foutput)
		defer w.Flush()
	}
	for item := range r.outputchan {
		if foutput != nil {
			// uses a buffer to write to file
			_, _ = w.WriteString(item + "\n")
		}
		// writes sequentially to stdout
		gologger.Silent().Msgf("%s\n", item)
	}
}

func (r *Runner) startOutputWorker() {
	// output worker
	r.outputchan = make(chan string)
	r.wgoutputworker.Add(1)
	go r.HandleOutput()
}

func (r *Runner) startWorkers() {
	if r.options.Stream {
		go r.InputWorkerStream()
	} else {
		go r.InputWorker()
	}

	r.startOutputWorker()
	// resolve workers
	for i := 0; i < r.options.Threads; i++ {
		r.wgresolveworkers.Add(1)
		go r.worker()
	}
}

func (r *Runner) worker() {
	defer r.wgresolveworkers.Done()
	for domain := range r.workerchan {
		if isURL(domain) {
			domain = extractDomain(domain)
		}
		r.limiter.Take()
		dnsData := dnsx.ResponseData{}
		// Ignoring errors as partial results are still good
		dnsData.DNSData, _ = r.dnsx.QueryMultiple(domain)
		// Just skipping nil responses (in case of critical errors)
		if dnsData.DNSData == nil {
			continue
		}

		if dnsData.Host == "" || dnsData.Timestamp.IsZero() {
			continue
		}

		// results from hosts file are always returned
		if !dnsData.HostsFile {
			// skip responses not having the expected response code
			if len(r.options.rcodes) > 0 {
				if _, ok := r.options.rcodes[dnsData.StatusCodeRaw]; !ok {
					continue
				}
			}
		}

		if !r.options.Raw {
			dnsData.Raw = ""
		}

		if r.options.Trace {
			dnsData.TraceData, _ = r.dnsx.Trace(domain)
			if dnsData.TraceData != nil {
				for _, data := range dnsData.TraceData.DNSData {
					if r.options.Raw && data.RawResp != nil {
						rawRespString := data.RawResp.String()
						data.Raw = rawRespString
						// join the whole chain in raw field
						dnsData.Raw += fmt.Sprintln(rawRespString)
					}
					data.RawResp = nil
				}
			}
		}

		if r.options.AXFR {
			hasAxfrData := false
			axfrData, _ := r.dnsx.AXFR(domain)
			if axfrData != nil {
				dnsData.AXFRData = axfrData
				hasAxfrData = len(axfrData.DNSData) > 0
			}

			// if the query type is only AFXR then output only if we have results (ref: https://github.com/projectdiscovery/dnsx/issues/230#issuecomment-1256659249)
			if len(r.dnsx.Options.QuestionTypes) == 1 && !hasAxfrData && !r.options.JSON {
				continue
			}
		}
		// add flags for cdn
		if r.options.OutputCDN {
			dnsData.IsCDNIP, dnsData.CDNName, _ = r.dnsx.CdnCheck(domain)
		}
		if r.options.ASN {
			results := []*asnmap.Response{}
			ips := dnsData.A
			if ips == nil {
				ips, _ = r.dnsx.Lookup(domain)
			}
			for _, ip := range ips {
				if data, err := asnmap.DefaultClient.GetData(ip); err == nil {
					results = append(results, data...)
				}
			}
			if iputil.IsIP(domain) {
				if data, err := asnmap.DefaultClient.GetData(domain); err == nil {
					results = append(results, data...)
				}
			}
			if len(results) > 0 {
				cidrs, _ := asnmap.GetCIDR(results)
				dnsData.ASN = &dnsx.AsnResponse{
					AsNumber:  fmt.Sprintf("AS%v", results[0].ASN),
					AsName:    results[0].Org,
					AsCountry: results[0].Country,
				}
				for _, cidr := range cidrs {
					dnsData.ASN.AsRange = append(dnsData.ASN.AsRange, cidr.String())
				}
			}
		}
		// if wildcard filtering just store the data
		if r.options.WildcardDomain != "" {
			if err := r.storeDNSData(dnsData.DNSData); err != nil {
				gologger.Debug().Msgf("Failed to store DNS data for %s: %v\n", domain, err)
			}
			continue
		}

		// if response type filter is set, we don't want to ignore them
		if len(r.options.responseTypeFilterMap) > 0 && r.shouldSkipRecord(&dnsData) {
			continue
		}

		if r.options.JSON {
			var marshalOptions []dnsx.MarshalOption
			if r.options.OmitRaw {
				marshalOptions = append(marshalOptions, dnsx.WithoutAllRecords())
			}
			jsons, _ := dnsData.JSON(marshalOptions...)
			r.outputchan <- jsons
			continue
		}
		if r.options.Raw {
			r.outputchan <- dnsData.Raw
			continue
		}

		// if response type filter is set, then print filtered records, moved to below from above block
		// coz json and raw flag support
		if len(r.options.responseTypeFilterMap) > 0 {
			r.outputRecordType(domain, dnsData.A, "A", dnsData.CDNName, dnsData.ASN)
			r.outputRecordType(domain, dnsData.AAAA, "AAAA", dnsData.CDNName, dnsData.ASN)
			r.outputRecordType(domain, dnsData.CNAME, "CNAME", dnsData.CDNName, dnsData.ASN)
			r.outputRecordType(domain, dnsData.MX, "MX", dnsData.CDNName, dnsData.ASN)
			r.outputRecordType(domain, dnsData.NS, "NS", dnsData.CDNName, dnsData.ASN)
			r.outputRecordType(domain, sliceutil.Dedupe(dnsData.GetSOARecords()), "SOA", dnsData.CDNName, dnsData.ASN)
			r.outputRecordType(domain, dnsData.TXT, "TXT", dnsData.CDNName, dnsData.ASN)
			r.outputRecordType(domain, dnsData.SRV, "SRV", dnsData.CDNName, dnsData.ASN)
			r.outputRecordType(domain, dnsData.CAA, "CAA", dnsData.CDNName, dnsData.ASN)
			r.outputRecordType(domain, dnsData.PTR, "PTR", dnsData.CDNName, dnsData.ASN)
			continue
		}

		if r.options.hasRCodes {
			r.outputResponseCode(domain, dnsData.StatusCodeRaw)
			continue
		}

		if r.options.A {
			r.outputRecordType(domain, dnsData.A, "A", dnsData.CDNName, dnsData.ASN)
		}
		if r.options.AAAA {
			r.outputRecordType(domain, dnsData.AAAA, "AAAA", dnsData.CDNName, dnsData.ASN)
		}
		if r.options.CNAME {
			r.outputRecordType(domain, dnsData.CNAME, "CNAME", dnsData.CDNName, dnsData.ASN)
		}
		if r.options.PTR {
			r.outputRecordType(domain, dnsData.PTR, "PTR", dnsData.CDNName, dnsData.ASN)
		}
		if r.options.MX {
			r.outputRecordType(domain, dnsData.MX, "MX", dnsData.CDNName, dnsData.ASN)
		}
		if r.options.NS {
			r.outputRecordType(domain, dnsData.NS, "NS", dnsData.CDNName, dnsData.ASN)
		}
		if r.options.SOA {
			r.outputRecordType(domain, sliceutil.Dedupe(dnsData.GetSOARecords()), "SOA", dnsData.CDNName, dnsData.ASN)
		}
		if r.options.ANY {
			allParsedRecords := sliceutil.Merge(
				dnsData.A,
				dnsData.AAAA,
				dnsData.CNAME,
				dnsData.MX,
				dnsData.PTR,
				sliceutil.Dedupe(dnsData.GetSOARecords()),
				dnsData.NS,
				dnsData.TXT,
				dnsData.SRV,
				dnsData.CAA,
			)
			r.outputRecordType(domain, allParsedRecords, "ANY", dnsData.CDNName, dnsData.ASN)
		}
		if r.options.TXT {
			r.outputRecordType(domain, dnsData.TXT, "TXT", dnsData.CDNName, dnsData.ASN)
		}
		if r.options.SRV {
			r.outputRecordType(domain, dnsData.SRV, "SRV", dnsData.CDNName, dnsData.ASN)
		}
		if r.options.CAA {
			r.outputRecordType(domain, dnsData.CAA, "CAA", dnsData.CDNName, dnsData.ASN)
		}
	}
}

func (r *Runner) outputRecordType(domain string, items interface{}, queryType, cdnName string, asn *dnsx.AsnResponse) {
	var details string
	if cdnName != "" {
		details = fmt.Sprintf(" [%s]", cdnName)
	}
	if asn != nil {
		details = fmt.Sprintf("%s %s", details, asn.String())
	}
	var records []string

	switch items := items.(type) {
	case []string:
		records = items
	case []retryabledns.SOA:
		for _, item := range items {
			records = append(records, item.NS, item.Mbox)
		}
	}

	for _, item := range records {
		item := strings.ToLower(item)
		if r.options.ResponseOnly {
			r.outputchan <- fmt.Sprintf("%s%s", item, details)
		} else if r.options.Response {
			r.outputchan <- fmt.Sprintf("%s [%s] [%s] %s", domain, r.aurora.Magenta(queryType), r.aurora.Green(item).String(), details)
		} else {
			// just prints out the domain if it has a record type and exit
			r.outputchan <- fmt.Sprintf("%s%s", domain, details)
			break
		}
	}
}

func (r *Runner) outputResponseCode(domain string, responsecode int) {
	responseCodeExt, ok := dns.RcodeToString[responsecode]
	if ok {
		r.outputchan <- domain + " [" + responseCodeExt + "]"
	}
}

func (r *Runner) shouldSkipRecord(dnsData *dnsx.ResponseData) bool {
	for _, et := range r.options.responseTypeFilterMap {
		switch strings.ToLower(strings.TrimSpace(et)) {
		case "a":
			if len(dnsData.A) > 0 {
				return true
			}
		case "aaaa":
			if len(dnsData.AAAA) > 0 {
				return true
			}
		case "cname":
			if len(dnsData.CNAME) > 0 {
				return true
			}
		case "ns":
			if len(dnsData.NS) > 0 {
				return true
			}
		case "txt":
			if len(dnsData.TXT) > 0 {
				return true
			}
		case "mx":
			if len(dnsData.MX) > 0 {
				return true
			}
		case "soa":
			if len(dnsData.SOA) > 0 {
				return true
			}
		case "srv":
			if len(dnsData.SRV) > 0 {
				return true
			}
		case "ptr":
			if len(dnsData.PTR) > 0 {
				return true
			}
		case "caa":
			if len(dnsData.CAA) > 0 {
				return true
			}
		default:
			return false
		}
	}
	return false
}

func (r *Runner) storeDNSData(dnsdata *retryabledns.DNSData) error {
	data, err := dnsdata.JSON()
	if err != nil {
		return err
	}
	return r.hm.Set(dnsdata.Host, []byte(data))
}

// Close running instance
func (r *Runner) Close() {
	r.hm.Close()
}

func (r *Runner) wildcardWorker() {
	defer r.wgwildcardworker.Done()

	for {
		host, more := <-r.wildcardworkerchan
		if !more {
			break
		}

		if r.IsWildcard(host) {
			// mark this host as a wildcard subdomain
			_ = r.wildcards.Set(host, struct{}{})
		}
	}
}
