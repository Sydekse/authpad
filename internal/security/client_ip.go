package security

import (
	"net"
	"net/http"
	"strings"
)

func ipTrusted(ip net.IP, trusted []*net.IPNet) bool {
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func hostIP(raw string) net.IP {
	raw = strings.TrimSpace(raw)
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	return net.ParseIP(strings.Trim(raw, "[]"))
}

// ClientIP returns the caller's address. X-Forwarded-For is honoured only when
// the connection's remote address is inside trusted (the configured proxies);
// then the header is walked right to left and the first address that is not a
// trusted proxy is the client. Without trusted proxies, or when the peer is
// not one, the remote address is used and the header is ignored. It returns ""
// when no address can be parsed.
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	peer := hostIP(r.RemoteAddr)
	if peer == nil {
		return ""
	}
	if len(trusted) == 0 || !ipTrusted(peer, trusted) {
		return peer.String()
	}
	var hops []string
	for _, v := range r.Header.Values("X-Forwarded-For") {
		hops = append(hops, strings.Split(v, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		ip := hostIP(hops[i])
		if ip == nil {
			// A garbage hop cannot be attributed; stop and use the last good one.
			break
		}
		if !ipTrusted(ip, trusted) {
			return ip.String()
		}
		if i == 0 {
			return ip.String()
		}
	}
	return peer.String()
}
