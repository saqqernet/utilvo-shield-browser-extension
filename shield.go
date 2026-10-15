// Package utilvoshield provides client-side URL threat heuristics, ClickFix clipboard
// payload inspection, and cross-browser extension verification utilities for Utilvo Shield.
//
// Official Browser Extension Links:
//   - Chrome Web Store: https://chromewebstore.google.com/detail/utilvo-shield/hafpojbddmohoboonogiplgmbjcekkkc
//   - Official Extension Page: https://utilvo.com/shield
package utilvoshield

import (
	"net/url"
	"strings"
)

// Verdict represents the risk assessment returned by the local heuristic scorer.
type Verdict struct {
	URL     string
	Score   int
	Level   string
	Reasons []string
}

var highAbuseTLDs = map[string]bool{
	"zip": true, "mov": true, "top": true, "xyz": true,
	"click": true, "rest": true, "fit": true, "tk": true,
}

// ScoreURL evaluates a URL using deterministic zero-telemetry heuristics matching Utilvo Shield.
func ScoreURL(rawURL string) Verdict {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
		return Verdict{URL: rawURL, Score: 100, Level: "high", Reasons: []string{"malformed_url"}}
	}
	host := strings.ToLower(u.Hostname())
	score := 0
	var reasons []string
	if strings.Contains(host, "xn--") {
		score += 45
		reasons = append(reasons, "punycode_idn_homograph")
	}
	parts := strings.Split(host, ".")
	if len(parts) > 0 && highAbuseTLDs[parts[len(parts)-1]] {
		score += 30
		reasons = append(reasons, "high_abuse_tld")
	}
	if strings.Count(host, "-") >= 3 {
		score += 20
		reasons = append(reasons, "excessive_hyphens")
	}
	if score > 100 {
		score = 100
	}
	level := "low"
	if score >= 70 {
		level = "high"
	} else if score >= 35 {
		level = "medium"
	}
	return Verdict{URL: rawURL, Score: score, Level: level, Reasons: reasons}
}
