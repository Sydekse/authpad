package security

import (
	"github.com/Sydekse/authpad/internal/apptypes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	trusted, err := apptypes.ParseCIDRs([]string{"10.0.0.0/8", "172.18.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, remote string
		xff          []string
		trusted      bool
		want         string
	}{
		{"no proxies configured ignores header", "10.1.1.1:80", []string{"1.2.3.4"}, false, "10.1.1.1"},
		{"untrusted peer ignores header", "203.0.113.9:80", []string{"1.2.3.4"}, true, "203.0.113.9"},
		{"trusted peer uses header", "10.1.1.1:80", []string{"198.51.100.7"}, true, "198.51.100.7"},
		{"spoofed left hop is skipped", "10.1.1.1:80", []string{"6.6.6.6, 198.51.100.7"}, true, "198.51.100.7"},
		{"trusted hops are skipped", "10.1.1.1:80", []string{"198.51.100.7, 10.2.2.2"}, true, "198.51.100.7"},
		{"single host entry", "172.18.0.5:80", []string{"198.51.100.7"}, true, "198.51.100.7"},
		{"trusted peer without header", "10.1.1.1:80", nil, true, "10.1.1.1"},
		{"all hops trusted", "10.1.1.1:80", []string{"10.3.3.3"}, true, "10.3.3.3"},
		{"garbage hop falls back to peer", "10.1.1.1:80", []string{"not-an-ip"}, true, "10.1.1.1"},
		{"multiple header lines", "10.1.1.1:80", []string{"6.6.6.6", "198.51.100.7"}, true, "198.51.100.7"},
		{"ipv6 client", "10.1.1.1:80", []string{"2001:db8::1"}, true, "2001:db8::1"},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = tc.remote
		for _, v := range tc.xff {
			r.Header.Add("X-Forwarded-For", v)
		}
		var nets = trusted
		if !tc.trusted && tc.name == "no proxies configured ignores header" {
			nets = nil
		}
		if got := ClientIP(r, nets); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
	if _, err := apptypes.ParseCIDRs([]string{"nonsense"}); err == nil {
		t.Fatal("invalid entry must error")
	}
}
