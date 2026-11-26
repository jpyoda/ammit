package analyzer

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/jpyoda/ammit/internal/finding"
	"github.com/jpyoda/ammit/internal/ir"
)

// References flags suspicious things an add-on points to.
type References struct{}

func (References) Name() string { return "references" }

var shorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true, "is.gd": true, "rb.gy": true,
	"cutt.ly": true, "shorturl.at": true, "ow.ly": true, "buff.ly": true, "tiny.cc": true, "rebrand.ly": true,
}

func (References) Analyze(_ context.Context, a *ir.Artifact) ([]finding.Finding, error) {
	var out []finding.Finding
	seen := map[string]bool{}
	for _, r := range a.References {
		if r.Type != "url" {
			continue
		}
		u, err := url.Parse(r.Value)
		if err != nil || u.Host == "" {
			continue
		}
		host := strings.ToLower(u.Hostname())
		var f *finding.Finding
		switch {
		case net.ParseIP(host) != nil && !isLocal(host):
			f = &finding.Finding{RuleID: "AMT-REF-001", Title: "Link to a raw IP address", Severity: finding.Medium,
				Category: "network", Message: "Points to " + host + " instead of a domain name, common for attacker infrastructure.", Confidence: 0.55}
		case shorteners[host]:
			f = &finding.Finding{RuleID: "AMT-REF-002", Title: "Shortened link", Severity: finding.Medium,
				Category: "network", Message: "A URL shortener hides the real destination, which can be changed at any time.", Confidence: 0.55}
		case strings.HasSuffix(host, ".invalid") || strings.HasSuffix(host, ".example"):
			continue
		}
		if f == nil || seen[f.RuleID+r.Value] {
			continue
		}
		seen[f.RuleID+r.Value] = true
		f.File, f.Line, f.Evidence = r.File, r.Line, r.Value
		out = append(out, *f)
	}
	return out, nil
}

// documentation ranges (RFC 5737) never route; they appear in examples.
var docNets = func() []*net.IPNet {
	var ns []*net.IPNet
	for _, c := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, n, _ := net.ParseCIDR(c)
		ns = append(ns, n)
	}
	return ns
}()

func isLocal(h string) bool {
	ip := net.ParseIP(h)
	if ip == nil {
		return false
	}
	for _, n := range docNets {
		if n.Contains(ip) {
			return true
		}
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified()
}
