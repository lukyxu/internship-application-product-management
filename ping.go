package main

import (
	"fmt"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

type ipConfig struct {
	isIpv4      bool
	network     string
	messageType icmp.Type
	replyType   icmp.Type
	protocol    int
}

type packet struct {
	timeout  bool
	dstIp    *net.IPAddr
	ttl      int
	duration time.Duration
}

var (
	ip4Config = ipConfig{
		isIpv4:      true,
		network:     "ip4:icmp",
		messageType: ipv4.ICMPTypeEcho,
		replyType:   ipv4.ICMPTypeEchoReply,
		protocol:    1,
	}

	ip6Config = ipConfig{
		isIpv4:      false,
		network:     "ip6:ipv6-icmp",
		messageType: ipv6.ICMPTypeEchoRequest,
		replyType:   ipv6.ICMPTypeEchoReply,
		protocol:    58,
	}
)

func main() {
	ttl := -1

	args := os.Args

	if len(args) <= 1 {
		fmt.Println("Usage: ping targetname (ttl)")
		os.Exit(1)
	}

	args = args[1:]

	if len(args) > 1 {
		var err error
		ttl, err = strconv.Atoi(args[1])
		if err != nil {
			fmt.Println("Second argument is integer for TTL")
			os.Exit(1)
		}
	}

	for {
		replyPacket, err := Ping(args[0], ttl)

		if err != nil {
			fmt.Println(err)
			return
		}

		if replyPacket.timeout {
			fmt.Printf("Request timed out\n")
		} else {
			fmt.Printf("Reply from %s: time=%dms TTL=%d\n", replyPacket.dstIp.IP.String(),
				replyPacket.duration.Milliseconds(), replyPacket.ttl)
		}

		time.Sleep(time.Second)
	}
}

func Ping(addr string, ttl int) (*packet, error) {
	dstIp, err := net.ResolveIPAddr("ip", addr)

	if err != nil {
		return nil, err
	}

	var ipc ipConfig
	if isIpv4(dstIp) {
		ipc = ip4Config
	} else if isIpv6(dstIp) {
		ipc = ip6Config
	} else {
		return nil, fmt.Errorf("invalid Host/IP address: %s", dstIp.IP.String())
	}

	c, err := icmp.ListenPacket(ipc.network, "0.0.0.0")

	if err != nil {
		return nil, err
	}

	defer c.Close()

	if ipc.isIpv4 {
		err = c.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
		if ttl != -1 {
			c.IPv4PacketConn().SetTTL(ttl)
		}
	} else {
		err = c.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
		if ttl != -1 {
			c.IPv6PacketConn().SetHopLimit(ttl)
		}
	}
	if err != nil {
		return nil, err
	}

	m := icmp.Message{
		Type: ipc.messageType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   0,
			Seq:  1,
			Data: []byte(""),
		},
	}

	bin, err := m.Marshal(nil)
	if err != nil {
		return nil, err
	}

	start := time.Now()

	size, err := c.WriteTo(bin, dstIp)
	if err != nil {
		return nil, err
	}
	if size != len(bin) {
		return nil, fmt.Errorf("unable to write complete packet to destination, got: %d, wanted: %d",
			size, len(bin))
	}

	buffer := make([]byte, 1000)
	err = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	if err != nil {
		return nil, err
	}

	outputPacket := packet{dstIp: dstIp}

	var n int
	if ipc.isIpv4 {
		var cm *ipv4.ControlMessage
		n, cm, _, err = c.IPv4PacketConn().ReadFrom(buffer)
		if cm != nil {
			outputPacket.ttl = cm.TTL
		}
	} else {
		var cm *ipv6.ControlMessage
		n, cm, _, err = c.IPv6PacketConn().ReadFrom(buffer)
		if cm != nil {
			outputPacket.ttl = cm.HopLimit
		}
	}

	if err != nil {
		if strings.Contains(err.Error(), "timeout") {
			outputPacket.timeout = true
			return &outputPacket, nil
		}
		return &outputPacket, err
	}

	if n != len(bin) {
		return nil, fmt.Errorf("incomplete response, got: %d, wanted: %d", n, len(bin))
	}

	outputPacket.duration = time.Since(start)

	message, err := icmp.ParseMessage(ipc.protocol, buffer[:size])

	if err != nil {
		return &outputPacket, err
	}

	if message.Type != ipc.replyType {
		return &outputPacket, fmt.Errorf("incompatible response type; got: %s, wanted %s",
			message.Type, ipc.replyType)
	}

	return &outputPacket, nil
}

func isIpv4(ip *net.IPAddr) bool {
	return ip.IP.To4() != nil
}

func isIpv6(ip *net.IPAddr) bool {
	return ip.IP.To16() != nil
}
