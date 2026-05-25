// dnx is a commandline DNS client for processing multiple hostnames
// (as arguments or on stdin) and reporting those that return NXDOMAIN
// on dns lookups. For safety, dnx does multiple typed lookups
// concurrently and only reports those that fail all tests.

package main

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/gavincarr/dany"
	flags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
)

const dnsPort = "53"

// Options
type Options struct {
	Verbose     bool   `short:"v" long:"verbose" description:"display verbose debug output"`
	Resolvers   string `short:"r" long:"resolv" description:"text file of ip addresses to use as resolvers"`
	Server      string `short:"s" long:"server" description:"ip address of server to use as resolver"`
	Concurrency int    `short:"C" long:"concurrency" description:"number of hostnames to query concurrently per resolver" default:"3"`
	Count       bool   `short:"c" long:"count" description:"report all domains and a count of non-NXDOMAIN responses, comma-separated"`
	Invert      bool   `short:"V" long:"invert" description:"report domains that do NOT return NXDOMAIN"`
	Types       string `short:"t" long:"types" description:"comma-separated DNS types to probe for NX detection (default: MX,NS,SOA)"`
	Args        struct {
		Hostname  string   `description:"hostname/domain to lookup"`
		Hostname2 []string `description:"additional hostnames/domains to lookup"`
	} `positional-args:"yes"`
}

var opts Options

// Disable flags.PrintErrors for more control
var parser = flags.NewParser(&opts, flags.Default&^flags.PrintErrors)

func usage() {
	parser.WriteHelp(os.Stderr)
	fmt.Fprintf(os.Stderr, "\nDefault NX-probe types: %s\n", strings.Join(dany.NXTypes, ","))
	fmt.Fprintf(os.Stderr, "Supported DNS resource types: %s\n", strings.Join(dany.SupportedRRTypes, ","))
	os.Exit(2)
}

func vprintf(format string, args ...interface{}) {
	if !opts.Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "+ "+format, args...)
}

// Parse options and return a set of resolvers and the list of types to probe
// (nil/empty means: let dany.RunNXQuery fall back to dany.NXTypes).
func parseOpts(opts Options) (*dany.Resolvers, []string, error) {
	var resolvers *dany.Resolvers
	var types []string
	var err error

	if opts.Types != "" {
		typeMap := make(map[string]bool)
		for _, t := range dany.SupportedRRTypes {
			typeMap[t] = true
			typeMap[strings.ToLower(t)] = true
		}
		types = strings.Split(opts.Types, ",")
		var bad []string
		for _, t := range types {
			if !typeMap[t] {
				bad = append(bad, t)
			}
		}
		if len(bad) > 0 {
			return nil, nil, fmt.Errorf("Error: unsupported types in %q: %s",
				opts.Types, strings.Join(bad, ","))
		}
	}

	if opts.Server != "" {
		// Parse opts.Server
		serverIP := net.ParseIP(opts.Server)
		if serverIP == nil {
			err = fmt.Errorf("Error: unable to parse --server ip address %q", opts.Server)
			return nil, nil, err
		}
		resolvers = dany.NewResolvers(serverIP)
	} else if opts.Resolvers != "" {
		// Parse opts.Resolvers
		resolvers, err = dany.LoadResolvers(opts.Resolvers)
		if err != nil {
			return nil, nil, err
		}
	} else {
		// No Server or Resolvers option set - use /etc/resolv.conf
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, nil, err
		}
		for _, server := range config.Servers {
			serverIP := net.ParseIP(server)
			if serverIP == nil {
				err = fmt.Errorf("Error: unable to parse --server ip address %q", opts.Server)
				return nil, nil, err
			}
			if resolvers == nil {
				resolvers = dany.NewResolvers(serverIP)
			} else {
				resolvers.Append(serverIP)
			}
		}
	}

	vprintf("resolvers: %v\n", resolvers.List)
	if len(types) > 0 {
		vprintf("types: %v\n", types)
	}

	return resolvers, types, nil
}

func processHostname(sem chan bool, hostname string, resolvers *dany.Resolvers, types []string) {
	// Release semaphore slot at end of function
	defer func() { <-sem }()

	server := net.JoinHostPort(resolvers.Next().String(), dnsPort)

	vprintf("looking up %s using %s\n", hostname, server)
	responseCount := dany.RunNXQuery(&dany.Query{Hostname: hostname, Server: server, Types: types})
	if opts.Count {
		fmt.Printf("%s,%d\n", hostname, responseCount)
		return
	}
	nxdomain := responseCount == 0
	if opts.Invert {
		nxdomain = !nxdomain
	}
	if nxdomain {
		fmt.Println(hostname)
	}
}

func main() {
	// Parse options
	if _, err := parser.Parse(); err != nil {
		if flagsErr, ok := err.(*flags.Error); ok && flagsErr.Type != flags.ErrHelp {
			fmt.Fprintf(os.Stderr, "%s\n\n", err)
		}
		usage()
	}

	// Setup
	log.SetFlags(0)
	resolvers, types, err := parseOpts(opts)
	if err != nil {
		log.Fatal(err)
	}
	// Setup a semaphore channel for limiting hostname concurrency
	concurrency := opts.Concurrency * resolvers.Length
	sem := make(chan bool, concurrency)

	if opts.Args.Hostname != "" {
		// opts.Args version
		args := []string{opts.Args.Hostname}
		if len(opts.Args.Hostname2) > 0 {
			args = append(args, opts.Args.Hostname2...)
		}

		// Do lookups
		for _, hostname := range args {
			sem <- true
			go processHostname(sem, hostname, resolvers, types)
		}
	} else {
		// Stdin version
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			hostname := scanner.Text()
			sem <- true
			go processHostname(sem, hostname, resolvers, types)
		}
	}
	// Wait for remaining goroutines by refilling all sem slots
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
}
