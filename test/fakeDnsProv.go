package test

import (
	"fmt"
	"github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
	"log"
	"strings"
)

type fakeDnsProv struct {
	Addr string
	mTxt map[string]string
	srv  *dns.Server
	mSoa map[string][2]string
}

func MakeFakeDnsProv(addr string) interface {
	challenge.Provider
	GetDnsAddrs() []string
	Start()
	Shutdown()
	AddRecursiveSOA(fqdn string)
} {
	return &fakeDnsProv{
		Addr: addr,
		mTxt: make(map[string]string),
		mSoa: make(map[string][2]string),
	}
}

func (f *fakeDnsProv) AddRecursiveSOA(fqdn string) {
	n := fqdn
	for {
		f.mSoa[n] = [2]string{"ns." + n, "webmaster." + n}

		// find next subdomain separator and trim the fqdn
		ni := strings.IndexByte(n, '.')
		if ni <= 0 {
			break
		}
		n = n[ni+1:]
	}
}

func (f *fakeDnsProv) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	f.mTxt[info.EffectiveFQDN] = info.Value
	log.Printf("fakeDnsProv.Present(%s TXT %s)\n", info.EffectiveFQDN, info.Value)
	return nil
}
func (f *fakeDnsProv) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	delete(f.mTxt, info.EffectiveFQDN)
	log.Printf("fakeDnsProv.CleanUp(%s TXT %s)\n", info.EffectiveFQDN, info.Value)
	return nil
}
func (f *fakeDnsProv) GetDnsAddrs() []string {
	fmt.Printf("Get dns addrs: %v\n", f.Addr)
	return []string{f.Addr}
}

func (f *fakeDnsProv) parseQuery(m *dns.Msg) {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeSOA:
			log.Printf("Looking up %s SOA record\n", q.Name)
			n := q.Name
			for strings.Count(n, ".") > 3 {
				// find next subdomain separator and trim the fqdn
				ni := strings.IndexByte(n, '.')
				if ni <= 0 {
					break
				}
				n = n[ni+1:]
			}

			// find an answer if possible
			if strings.Count(q.Name, ".") == 3 {
				rr, err := dns.NewRR(fmt.Sprintf("%s 32600 IN SOA %s %s 1687993787 86400 7200 4000000 11200", n, "ns.example.com.", "hostmaster.example.com."))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeTXT:
			log.Printf("Looking up %s TXT record\n", q.Name)
			txt := f.mTxt[q.Name]
			if txt != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s 32600 IN TXT \"%s\"", q.Name, txt))
				if err == nil {
					fmt.Println("response:", rr.String())
					m.Answer = append(m.Answer, rr)
				}
			}
		default:
			log.Printf("Looking up %d for %s\n", q.Qtype, q.Name)
		}
	}
}

func (f *fakeDnsProv) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		f.parseQuery(m)
	}

	_ = w.WriteMsg(m)
}

func (f *fakeDnsProv) Start() {
	// attach request handler func
	dns.HandleFunc(".", f.handleDnsRequest)

	// start server
	f.srv = &dns.Server{Addr: f.Addr, Net: "udp"}
	log.Printf("Starting fake dns service at %s\n", f.srv.Addr)
	err := f.srv.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start server: %s\n ", err.Error())
	}
}

func (f *fakeDnsProv) Shutdown() {
	_ = f.srv.Shutdown()
}
