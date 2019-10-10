// dnx is a commandline DNS client for processing multiple hostnames (as arguments or on
// stdin) and reporting those that return NXDOMAIN on dns lookups. For safety, dnx does
// multiple typed lookups concurrently and only reports those that fail all tests.

package main

import (
	"bufio"
	dany "dany/pkg"
	"fmt"
	"log"
	"net"
	"os"

	flags "github.com/jessevdk/go-flags"
	"github.com/miekg/dns"
)

const dnsPort = "53"

// Options
type Options struct {
	Verbose     bool   `short:"v" long:"verbose" description:"display verbose debug output"`
	Resolvers   string `short:"r" long:"resolv" description:"text file of ip addresses to use as resolvers"`
	Server      string `short:"s" long:"server" description:"ip address of server to use as resolver"`
	Concurrency int    `short:"c" description:"number of hostnames to query concurrently per resolver" default:"3"`
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
	os.Exit(2)
}

func vprintf(format string, args ...interface{}) {
	if !opts.Verbose {
		return
	}
	fmt.Fprintf(os.Stderr, "+ "+format, args...)
}

// Parse options and return a set of resolvers
func parseOpts(opts Options) (*dany.Resolvers, error) {
	var resolvers *dany.Resolvers
	var err error

	if opts.Server != "" {
		// Parse opts.Server
		serverIP := net.ParseIP(opts.Server)
		if serverIP == nil {
			err = fmt.Errorf("Error: unable to parse --server ip address %q", opts.Server)
			return nil, err
		}
		resolvers = dany.NewResolvers(serverIP)
	} else if opts.Resolvers != "" {
		// Parse opts.Resolvers
		resolvers, err = dany.LoadResolvers(opts.Resolvers)
		if err != nil {
			return nil, err
		}
	} else {
		// No Server or Resolvers option set - use /etc/resolv.conf
		config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, err
		}
		for _, server := range config.Servers {
			serverIP := net.ParseIP(server)
			if serverIP == nil {
				err = fmt.Errorf("Error: unable to parse --server ip address %q", opts.Server)
				return nil, err
			}
			if resolvers == nil {
				resolvers = dany.NewResolvers(serverIP)
			} else {
				resolvers.Append(serverIP)
			}
		}
	}

	vprintf("resolvers: %v\n", resolvers.List)

	return resolvers, nil
}

func processHostname(sem chan bool, hostname string, resolvers *dany.Resolvers) {
	// Release semaphore slot at end of function
	defer func() { <-sem }()

	server := net.JoinHostPort(resolvers.Next().String(), dnsPort)

	vprintf("looking up %s using %s\n", hostname, server)
	nxdomain, err := dany.RunNXQuery(hostname, server)
	vprintf("processing results for %s\n", hostname)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
	}
	if nxdomain {
		fmt.Fprintln(os.Stdout, hostname)
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
	resolvers, err := parseOpts(opts)
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
			go processHostname(sem, hostname, resolvers)
		}
	} else {
		// Stdin version
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			hostname := scanner.Text()
			sem <- true
			go processHostname(sem, hostname, resolvers)
		}
	}
	// Wait for remaining goroutines by refilling all sem slots
	for i := 0; i < cap(sem); i++ {
		sem <- true
	}
}
