// Package testdns is a tiny in-process DNS server for tests. Bind it to a
// random local port, register canned RR sets per (name, type), and point
// dany.Query.Server at Server.Addr.
//
// Semantics map onto real DNS:
//   - A name with at least one Add'd RR exists; unrequested qtypes return
//     NoError + no answer (i.e. NoData).
//   - A name with no Add'd RRs returns NXDOMAIN for every qtype.
//   - Use SetRcode to override with SERVFAIL, REFUSED, etc.
//
// Both UDP and TCP are served on the same port.
package testdns

import (
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/miekg/dns"
)

// Server is an in-process DNS server for tests. Construct with New.
type Server struct {
	Addr string // "127.0.0.1:NNNN" — assign to dany.Query.Server

	mu       sync.RWMutex
	names    map[string]map[uint16][]dns.RR // name → qtype → answers
	rcodes   map[string]int                 // name+"/"+qtype → rcode override
	udp, tcp *dns.Server
}

// New starts a server on a random local port. It is shut down automatically
// when the test ends.
func New(t *testing.T) *Server {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("testdns: ListenPacket udp: %v", err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr).String()
	tcpL, err := net.Listen("tcp", addr)
	if err != nil {
		pc.Close()
		t.Fatalf("testdns: Listen tcp: %v", err)
	}

	s := &Server{
		Addr:   addr,
		names:  make(map[string]map[uint16][]dns.RR),
		rcodes: make(map[string]int),
	}
	s.udp = &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(s.handle)}
	s.tcp = &dns.Server{Listener: tcpL, Handler: dns.HandlerFunc(s.handle)}

	started := make(chan struct{}, 2)
	s.udp.NotifyStartedFunc = func() { started <- struct{}{} }
	s.tcp.NotifyStartedFunc = func() { started <- struct{}{} }
	go s.udp.ActivateAndServe()
	go s.tcp.ActivateAndServe()
	<-started
	<-started

	t.Cleanup(func() {
		s.udp.Shutdown()
		s.tcp.Shutdown()
	})
	return s
}

// Add registers an RR as part of the canned response for its name+type. Call
// multiple times to build an RRset.
func (s *Server) Add(rr dns.RR) {
	name := strings.ToLower(dns.Fqdn(rr.Header().Name))
	qtype := rr.Header().Rrtype
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.names[name] == nil {
		s.names[name] = make(map[uint16][]dns.RR)
	}
	s.names[name][qtype] = append(s.names[name][qtype], rr)
}

// AddEmpty registers name as existing with no records, so every qtype returns
// NoError + no answer (NoData) — modeling a DNS empty non-terminal (a node
// that exists only because names below it do, e.g. _domainkey.<domain> when
// <selector>._domainkey.<domain> records exist).
func (s *Server) AddEmpty(name string) {
	name = strings.ToLower(dns.Fqdn(name))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.names[name] == nil {
		s.names[name] = make(map[uint16][]dns.RR)
	}
}

// SetRcode forces a non-default rcode for the given name+type, overriding any
// Add'd answers. Useful for simulating SERVFAIL, REFUSED, etc.
func (s *Server) SetRcode(name string, qtype uint16, rcode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rcodes[rcodeKey(name, qtype)] = rcode
}

func rcodeKey(name string, qtype uint16) string {
	return strings.ToLower(dns.Fqdn(name)) + "/" + dns.TypeToString[qtype]
}

func (s *Server) handle(w dns.ResponseWriter, req *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(req)
	m.Authoritative = true

	if len(req.Question) == 0 {
		m.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(m)
		return
	}
	q := req.Question[0]
	name := strings.ToLower(q.Name)

	s.mu.RLock()
	if rc, ok := s.rcodes[rcodeKey(name, q.Qtype)]; ok {
		s.mu.RUnlock()
		m.Rcode = rc
		_ = w.WriteMsg(m)
		return
	}
	byType, exists := s.names[name]
	if !exists {
		s.mu.RUnlock()
		m.Rcode = dns.RcodeNameError // NXDOMAIN
		_ = w.WriteMsg(m)
		return
	}
	m.Answer = append(m.Answer, byType[q.Qtype]...)
	// Real DNS behavior: if the name has a CNAME and no record of the
	// requested type, return the CNAME so the client can chase it.
	if len(m.Answer) == 0 && q.Qtype != dns.TypeCNAME {
		m.Answer = append(m.Answer, byType[dns.TypeCNAME]...)
	}
	s.mu.RUnlock()
	// Name exists but no records for this type and no CNAME → NoData.
	_ = w.WriteMsg(m)
}

// MustRR parses a zone-format RR line, panicking on error. Convenient for
// test fixtures.
func MustRR(s string) dns.RR {
	rr, err := dns.NewRR(s)
	if err != nil {
		panic(err)
	}
	return rr
}
