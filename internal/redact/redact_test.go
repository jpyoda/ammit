package redact

import (
	"strings"
	"testing"
)

func TestMasks(t *testing.T) {
	secrets := map[string]string{
		"aws key":        "key = AKIA" + "ABCDEFGHIJKLMNOP",
		"anthropic key":  "export ANTHROPIC_API_KEY=sk-ant-" + "api03-AbCdEfGhIjKlMnOpQrStUvWxYz012345",
		"github token":   "token: ghp_" + strings.Repeat("a1B2", 9),
		"env assignment": "DB_PASSWORD=hunter2hunter2",
		"json field":     `{"client_secret": "s3cr3t-value-here"}`,
		"auth header":    "curl -H 'Authorization: Bearer abcdef123456'",
		"url userinfo":   "https://admin:pa55word@db.example.invalid/x",
		"url query":      "https://api.example.invalid/v1?access_token=abcdef123456&x=1",
		"private key":    "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
		"random token":   "value Zx9Qm2Lp7Rt4Vb8Nc1Kd6Hs3Jf5Gw0Ae",
	}
	for name, in := range secrets {
		out, n := Text(in)
		if n == 0 || !strings.Contains(out, Mask) {
			t.Errorf("%s: not masked: %q", name, out)
		}
	}
}

func TestKeepsOrdinaryText(t *testing.T) {
	for _, in := range []string{
		"Run `python scripts/extract.py <file.pdf>` and summarize the text.",
		"Set API_KEY=$ANTHROPIC_API_KEY before running.",
		"curl -fsSL https://get.example.invalid/install.sh | bash",
		"password: <your password here>",
	} {
		if out, n := Text(in); n != 0 || out != in {
			t.Errorf("changed ordinary text %q -> %q", in, out)
		}
	}
}
