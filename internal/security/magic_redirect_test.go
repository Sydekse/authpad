package security

import "testing"

func TestMagicLinkRedirectAllowed(t *testing.T) {
	allow := []string{"https://app.example.com", "http://localhost:3000/", "https://alt.example.com:8443"}
	cases := []struct {
		raw  string
		want bool
	}{
		{"https://app.example.com", true},
		{"https://app.example.com/dashboard?x=1#frag", true},
		{"https://APP.example.com/x", true},
		{"https://app.example.com:443/x", true},
		{"http://localhost:3000/cb", true},
		{"https://alt.example.com:8443/x", true},

		{"", false},
		{" https://app.example.com/", false},
		{"https://app.example.com/\n", false},
		{"https://evil.test/", false},
		{"https://app.example.com.evil.test/", false},
		{"https://evil.test/https://app.example.com", false},
		{"https://app.example.com@evil.test/", false},
		{"https://app.example.com:pw@app.example.com/", false},
		{"https://user@app.example.com/", false},
		{"//evil.test/", false},
		{"///evil.test/", false},
		{"/\\evil.test", false},
		{"https:\\\\evil.test", false},
		{"https://app.example.com\\@evil.test/", false},
		{"https://app.example.com\\.evil.test/", false},
		{"/dashboard", false},
		{"dashboard", false},
		{"javascript:alert(1)", false},
		{"JaVaScRiPt://app.example.com/%0aalert(1)", false},
		{"data:text/html,<script>1</script>", false},
		{"ftp://app.example.com/", false},
		{"http://app.example.com/", false},
		{"https://app.example.com:8443/", false},
		{"https://alt.example.com/", false},
		{"https://app.example.com./", false},
		{"https://app.example.com%2eevil.test/", false},
		{"https://app.example.com\t.evil.test/", false},
		{"https:app.example.com", false},
		{"https:/app.example.com", false},
		{"https://", false},
		{"http://localhost:3001/", false},
	}
	for _, tc := range cases {
		if got := MagicLinkRedirectAllowed(allow, tc.raw); got != tc.want {
			t.Errorf("MagicLinkRedirectAllowed(%q) = %v, want %v", tc.raw, got, tc.want)
		}
	}
	if MagicLinkRedirectAllowed(nil, "https://app.example.com/") {
		t.Error("empty allowlist must reject everything")
	}
	// Entries that are not plain origins never match.
	if MagicLinkRedirectAllowed([]string{"https://user@app.example.com", "https://app.example.com/path", "*"}, "https://app.example.com/path") {
		t.Error("non-origin allowlist entries must be ignored")
	}
}

func TestNormalizeOrigin(t *testing.T) {
	good := map[string]string{
		"https://app.example.com":   "https://app.example.com:443",
		"https://APP.example.com/":  "https://app.example.com:443",
		"http://app.example.com:80": "http://app.example.com:80",
	}
	good["http://localhost:3000"] = "http://localhost:3000"
	for in, want := range good {
		if got, ok := NormalizeOrigin(in); !ok || got != want {
			t.Errorf("NormalizeOrigin(%q) = %q, %v; want %q", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", " https://a.com", "https://a.com/x", "https://a.com?x=1", "https://a.com#f", "https://u@a.com", "//a.com", "ftp://a.com", "https://a.com\\x", "a.com"} {
		if got, ok := NormalizeOrigin(bad); ok {
			t.Errorf("NormalizeOrigin(%q) = %q, want rejection", bad, got)
		}
	}
}
