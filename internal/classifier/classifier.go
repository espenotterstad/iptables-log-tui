package classifier

import "net"

const (
	CatInternal  = "Internal"
	CatMulticast = "Multicast"
	CatExternal  = "External"
)

var multicastRanges []*net.IPNet

func init() {
	_, v4, _ := net.ParseCIDR("224.0.0.0/4")
	_, v6, _ := net.ParseCIDR("ff00::/8")
	multicastRanges = []*net.IPNet{v4, v6}
}

type Classifier struct{ subnets []*net.IPNet }

func New() *Classifier {
	ifaces, err := net.Interfaces()
	if err != nil {
		return &Classifier{}
	}
	var nets []*net.IPNet
	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if n, ok := addr.(*net.IPNet); ok {
				nets = append(nets, n)
			}
		}
	}
	return &Classifier{subnets: nets}
}

func (c *Classifier) Categorize(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return CatExternal
	}
	for _, r := range multicastRanges {
		if r.Contains(ip) {
			return CatMulticast
		}
	}
	for _, s := range c.subnets {
		if s.Contains(ip) {
			return CatInternal
		}
	}
	return CatExternal
}
