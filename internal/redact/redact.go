// Package redact masks secrets before any text leaves the machine.
//
// It runs on everything the LLM judge sends to a model provider. It masks
// known credential formats, values of secret-looking variables, HTTP
// authorization headers, URL query values and userinfo, and long
// high-entropy strings (an approach adapted from Snyk agent-scan). It
// over-masks on purpose: a masked hash costs the judge little, a leaked key
// costs the user a lot.
package redact

import (
	"math"
	"regexp"
	"strings"
)

// Mask replaces a secret value.
const Mask = "[REDACTED]"

var (
	known = regexp.MustCompile(`\b(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|gho_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,}|` +
		`sk-ant-[A-Za-z0-9_-]{20,}|sk-(?:proj-)?[A-Za-z0-9_-]{32,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{35}|` +
		`glpat-[A-Za-z0-9_-]{20,}|npm_[A-Za-z0-9]{36}|hf_[A-Za-z0-9]{30,})\b`)
	privateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)`)
	// NAME=value, NAME: value, "name": "value" where NAME looks secret.
	assign = regexp.MustCompile(`(?i)\b([A-Za-z0-9_.-]*(?:secret|token|passw(?:or)?d|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential|auth)[A-Za-z0-9_.-]*)` +
		`(["']?\s*[:=]\s*["']?)([^\s"'` + "`" + `,;]{4,})`)
	authHeader = regexp.MustCompile(`(?i)\b(authorization|proxy-authorization|x-api-key|api-key)(\s*[:=]\s*)(?:(bearer|basic|token)\s+)?([^\s"'` + "`" + `]{4,})`)
	urlCreds   = regexp.MustCompile(`(https?://)([^/\s:@]+):([^/\s@]+)@`)
	urlQuery   = regexp.MustCompile(`([?&][A-Za-z0-9_.-]+=)([^&\s"'#` + "`" + `)]{6,})`)
	token      = regexp.MustCompile(`[A-Za-z0-9+/_=-]{32,}`)
)

// Text masks secrets in s and returns the result and how many values it masked.
func Text(s string) (string, int) {
	n := 0
	count := func(re *regexp.Regexp, repl func([]string) string) {
		s = re.ReplaceAllStringFunc(s, func(m string) string {
			sub := re.FindStringSubmatch(m)
			out := repl(sub)
			if out != m {
				n++
			}
			return out
		})
	}
	count(privateKey, func([]string) string { return "-----BEGIN PRIVATE KEY----- " + Mask + " -----END PRIVATE KEY-----" })
	count(known, func([]string) string { return Mask })
	count(authHeader, func(m []string) string {
		scheme := ""
		if m[3] != "" {
			scheme = m[3] + " "
		}
		return m[1] + m[2] + scheme + Mask
	})
	count(urlCreds, func(m []string) string { return m[1] + Mask + "@" })
	count(urlQuery, func(m []string) string { return m[1] + Mask })
	count(assign, func(m []string) string {
		if m[3] == Mask || strings.HasPrefix(m[3], "$") || strings.HasPrefix(m[3], "<") || strings.HasPrefix(m[3], "{") {
			return m[0] // a reference or placeholder, not a value
		}
		return m[1] + m[2] + Mask
	})
	count(token, func(m []string) string {
		if highEntropy(m[0]) {
			return Mask
		}
		return m[0]
	})
	return s, n
}

// highEntropy flags random-looking strings: mixed character classes and
// Shannon entropy above 4 bits per character. Long words, paths and hex
// digests of 32 or more characters also get masked; that is accepted.
func highEntropy(s string) bool {
	if strings.Contains(s, "/") && strings.Count(s, "/") > 2 {
		return false // a path
	}
	var lower, upper, digit bool
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
		switch {
		case r >= 'a' && r <= 'z':
			lower = true
		case r >= 'A' && r <= 'Z':
			upper = true
		case r >= '0' && r <= '9':
			digit = true
		}
	}
	classes := 0
	for _, b := range []bool{lower, upper, digit} {
		if b {
			classes++
		}
	}
	if classes < 2 {
		return false
	}
	h := 0.0
	for _, c := range freq {
		p := c / float64(len(s))
		h -= p * math.Log2(p)
	}
	return h > 4.0
}
