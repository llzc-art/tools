package service

import (
	"fmt"
	"net"
)

type IPService struct{}

func NewIPService() *IPService {
	return &IPService{}
}

type IPLookupResult struct {
	IP      string `json:"ip"`
	Version string `json:"version"`
	IsIPv4  bool   `json:"is_ipv4"`
	IsIPv6  bool   `json:"is_ipv6"`
}

func (s *IPService) Lookup(ipStr string) (*IPLookupResult, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil, fmt.Errorf("无效的 IP 地址: %s", ipStr)
	}

	isIPv4 := ip.To4() != nil
	version := "IPv6"
	if isIPv4 {
		version = "IPv4"
	}

	return &IPLookupResult{
		IP:      ipStr,
		Version: version,
		IsIPv4:  isIPv4,
		IsIPv6:  !isIPv4,
	}, nil
}

type IPCIDRResult struct {
	CIDR      string `json:"cidr"`
	Network   string `json:"network"`
	Mask      string `json:"mask"`
	FirstIP   string `json:"first_ip"`
	LastIP    string `json:"last_ip"`
	HostCount int64  `json:"host_count"`
}

func (s *IPService) CIDR(cidr string) (*IPCIDRResult, error) {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	mask := ipNet.Mask
	ones, bits := mask.Size()
	hostCount := int64(1)<<(bits-ones) - 2
	if hostCount < 0 {
		hostCount = 0
	}

	// 计算第一个和最后一个可用 IP
	networkIP := ipNet.IP
	firstIP := make(net.IP, len(networkIP))
	copy(firstIP, networkIP)
	if len(firstIP) == net.IPv4len {
		firstIP[3]++
	}

	lastIP := make(net.IP, len(networkIP))
	copy(lastIP, networkIP)
	for i := range lastIP {
		lastIP[i] = networkIP[i] | ^mask[i]
	}
	if len(lastIP) == net.IPv4len {
		lastIP[3]--
	}

	return &IPCIDRResult{
		CIDR:      cidr,
		Network:   ipNet.String(),
		Mask:      net.IP(mask).String(),
		FirstIP:   firstIP.String(),
		LastIP:    lastIP.String(),
		HostCount: hostCount,
	}, nil
}
