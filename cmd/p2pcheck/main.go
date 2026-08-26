// Command p2pcheck runs the recovered KwMV P2P handshake against the live
// tracker so the chain can be verified on a network with unrestricted UDP
// (the dev sandbox drops outbound UDP entirely).
//
// Usage:
//
//	go run ./cmd/p2pcheck <sig1> <sig2>
//
// e.g. sig pair for MUSIC_169753: 3264614461 1651339078
package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"

	"kuwoapi/module/p2p"
)

// public DNS used because Android lacks /etc/resolv.conf
const dnsServer = "8.8.8.8:53"

func main() {
	sig1, sig2 := uint32(3264614461), uint32(1651339078)
	if len(os.Args) >= 3 {
		a, _ := strconv.ParseUint(os.Args[1], 10, 32)
		b, _ := strconv.ParseUint(os.Args[2], 10, 32)
		sig1, sig2 = uint32(a), uint32(b)
	}
	// anonymous uid per KwMV.dll 0x10012b21: (FNV1a(machine) mod 1e8) + 1e8
	uid := uint32(152776543)

	fmt.Println("== stage 0: UDP egress sanity (standard DNS over UDP) ==")
	stage0OK := false
	for _, dns := range []string{"223.5.5.5:53", "8.8.8.8:53"} {
		dc, err := net.DialTimeout("udp", dns, 3*time.Second)
		if err != nil {
			fmt.Printf("  %s dial: %v\n", dns, err)
			continue
		}
		// standard query: A record for www.kuwo.cn
		q := []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			3, 'w', 'w', 'w', 4, 'k', 'u', 'w', 'o', 2, 'c', 'n', 0,
			0x00, 0x01, 0x00, 0x01,
		}
		dc.SetReadDeadline(time.Now().Add(2500 * time.Millisecond))
		if _, err := dc.Write(q); err != nil {
			fmt.Printf("  %s write: %v\n", dns, err)
		} else {
			buf := make([]byte, 512)
			if n, err := dc.Read(buf); err != nil {
				fmt.Printf("  %s: NO REPLY (%v) -> UDP egress blocked/filtered\n", dns, err)
			} else {
				stage0OK = true
				fmt.Printf("  %s: DNS reply %dB -> UDP egress OK\n", dns, n)
			}
		}
		dc.Close()
	}

	fmt.Println("\n== stage 0.5: pull live server list from config.kuwo.cn ==")
	// Android has no /etc/resolv.conf so Go's resolver defaults to [::1]:53 and
	// fails; query a public DNS explicitly instead.
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", dnsServer)
		},
	}
	p2p.SetConfigResolver(resolver)
	hbAddrs := []*net.UDPAddr{}
	trkAddrs := []*net.UDPAddr{}
	helpAddrs := []*net.UDPAddr{}
	if ini, err := p2p.FetchServerConfig(strconv.FormatUint(uint64(uid), 10)); err != nil {
		fmt.Println("config fetch failed:", err)
	} else {
		fmt.Printf("config INI %d bytes\n", len(ini))
		for _, s := range p2p.HeartbeatServersFromConfig(ini) {
			if ip, port, err := net.SplitHostPort(s); err == nil {
				hbAddrs = append(hbAddrs, &net.UDPAddr{IP: net.ParseIP(ip), Port: mustAtoi(port)})
			}
		}
		for _, ipStr := range p2p.SearchServersFromConfig(ini) {
			trkAddrs = append(trkAddrs, &net.UDPAddr{IP: net.ParseIP(ipStr), Port: 25607})
		}
		fmt.Println("heartbeat servers:", hbAddrs)
		fmt.Println("search/tracker servers:", trkAddrs)
	}
	if len(hbAddrs) == 0 {
		hbAddrs = append(hbAddrs, &net.UDPAddr{IP: net.ParseIP("175.102.178.96"), Port: 25607})
	}

	fmt.Println("\n== stage 1: heartbeat registration ==")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// deliver.kuwo.cn DNS IPs stay first in the tracker list (act.log evidence)
	ips, err := resolver.LookupNetIP(ctx, "ip4", "deliver.kuwo.cn")
	if err == nil && len(ips) > 0 {
		for _, ip := range ips {
			a := &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: 25607}
			dup := false
			for _, t := range trkAddrs {
				if t.IP.String() == a.IP.String() {
					dup = true
					break
				}
			}
			if !dup {
				trkAddrs = append([]*net.UDPAddr{a}, trkAddrs...)
			}
		}
		fmt.Println("tracker resolves to", ips)
	}
	if len(trkAddrs) == 0 {
		trkAddrs = append(trkAddrs, &net.UDPAddr{IP: net.ParseIP("39.156.121.53"), Port: 25607})
	}

	uc, err := net.ListenUDP("udp", &net.UDPAddr{Port: 6000})
	if err != nil {
		fmt.Printf("bind :6000 failed (%v), using ephemeral port\n", err)
		uc, err = net.ListenUDP("udp", &net.UDPAddr{Port: 0})
		if err != nil {
			fmt.Println("bind:", err)
			return
		}
	}
	defer uc.Close()
	fmt.Printf("local udp port: %d (server-pushed P2P port is 6000)\n", uc.LocalAddr().(*net.UDPAddr).Port)
	p2p.Verbose = true

	// outbound IP for the probe packet
	conn, err := net.DialTimeout("udp", dnsServer, 3*time.Second)
	if err != nil {
		fmt.Println("local ip probe:", err)
		return
	}
	localIP := net.ParseIP(conn.LocalAddr().(*net.UDPAddr).IP.String()).To4()
	conn.Close()
	lport := uint16(uc.LocalAddr().(*net.UDPAddr).Port)

	// help servers from libp2p.so defaults (P2P_HelpSvr1/2, docs §10.62)
	for _, h := range p2p.DefaultHelpServers {
		host, port, _ := net.SplitHostPort(h)
		ha, err := resolver.LookupNetIP(ctx, "ip4", host)
		if err != nil {
			fmt.Printf("resolve %s: %v\n", host, err)
			continue
		}
		helpAddrs = append(helpAddrs, &net.UDPAddr{IP: net.IP(ha[0].AsSlice()), Port: mustAtoi(port)})
	}
	targets := append(append([]*net.UDPAddr{}, helpAddrs...), hbAddrs...)
	targets = append(targets, trkAddrs...)

	seq := uint8(1)
	probe := p2p.NATProbe(seq, uid, binary.BigEndian.Uint32(localIP), lport)
	fmt.Println("== stage 1a: Android-protocol NAT probe (cmd 0x29, keepalive) ==")
	fmt.Printf("probe %dB -> %d targets\n", len(probe), len(targets))
	sawReply := false
	var extIP uint32
	var extPort uint16
	for i := 0; i < 5; i++ {
		for _, a := range targets {
			uc.WriteTo(probe, a)
		}
		buf := make([]byte, 2048)
		deadline := time.Now().Add(time.Duration(len(targets)) * 400 * time.Millisecond)
		for time.Now().Before(deadline) {
			uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, from, err := uc.ReadFrom(buf)
			if err != nil {
				break
			}
			sawReply = true
			class, cmd, payload, ok := p2p.Classify(buf[:n])
			fmt.Printf("REPLY from %v (%dB) class=%d cmd=0x%02x\n", from, n, class, cmd)
			fmt.Print(hex.Dump(buf[:n]))
			if !ok {
				continue
			}
			switch cmd {
			case p2p.CmdNATProbeACK:
				if ip, port, ok := p2p.NATProbeACK(payload, uid); ok {
					extIP, extPort = ip, port
					fmt.Printf("  -> TNATProbeMsg ext=%d.%d.%d.%d:%d nat=0/2/4 tree applies\n",
						byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port)
				}
			case p2p.CmdHeartbeatACK:
				if ip, port, ok := p2p.HeartbeatACK(payload); ok {
					extIP, extPort = ip, port
					fmt.Printf("  -> ACK_HEARTBEAT_INFO ext=%d.%d.%d.%d:%d\n",
						byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port)
				}
			case p2p.CmdPassiveConnect:
				if ip, port, ok := p2p.PassiveConnectReq(payload); ok {
					fmt.Printf("  -> PASSIVE CONNECT to %d.%d.%d.%d:%d\n",
						byte(ip>>24), byte(ip>>16), byte(ip>>8), byte(ip), port)
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	if sawReply && extIP != 0 {
		ip := localIP
		fmt.Printf("registered! external endpoint %d.%d.%d.%d:%d (local %s:%d)\n",
			byte(extIP>>24), byte(extIP>>16), byte(extIP>>8), byte(extIP), extPort, ip, lport)
	} else if sawReply {
		fmt.Println("replies seen but no external endpoint extracted yet")
	} else if stage0OK {
		fmt.Println("(no reply to cmd 0x29 while DNS-over-UDP works -> format or target mismatch)")
	}

	fmt.Println("\n== stage 1b: legacy PC heartbeat (KwMV 0xE2103) as control ==")
	hbZero := p2p.Heartbeat{UID: uid, NAT: 3, Port: lport, IP: 0}
	for i := 0; i < 2; i++ {
		for _, a := range targets {
			uc.WriteTo(hbZero.Marshal(), a)
		}
		buf := make([]byte, 2048)
		deadline := time.Now().Add(time.Duration(len(targets)) * 400 * time.Millisecond)
		for time.Now().Before(deadline) {
			uc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, from, err := uc.ReadFrom(buf)
			if err != nil {
				break
			}
			fmt.Printf("REPLY from %v (%dB): % x\n", from, n, buf[:n])
		}
		time.Sleep(300 * time.Millisecond)
	}

	fmt.Println("\n== stage 2: CSF session + U_QRY (3 attempts per tracker) ==")
	var sess *p2p.Session
outer:
	for _, trk := range trkAddrs {
		for attempt := 1; attempt <= 3; attempt++ {
			src := ""
			if uc.LocalAddr().(*net.UDPAddr).Port == 6000 {
				src = ":6000"
			}
			s, err := p2p.Dial(src, trk, uid)
			if err == nil {
				sess = s
				fmt.Printf("handshake OK via %v on attempt %d (lport=%d)\n", trk, attempt, s.LocalPort())
				break outer
			}
			fmt.Printf("%v attempt %d: %v\n", trk, attempt, err)
			time.Sleep(500 * time.Millisecond)
		}
	}
	if sess == nil {
		if stage0OK {
			fmt.Println("(all 3 attempts no SYNACK while DNS-over-UDP works -> server ignores our SYN or port 25607/udp is specifically filtered)")
		} else {
			fmt.Println("(no SYNACK and even DNS over UDP fails -> carrier blocks UDP egress)")
		}
		return
	}
	defer sess.Close()

	req := p2p.BuildUQRY(p2p.QueryParams{
		UID:     uid,
		Sig1:    sig1,
		Sig2:    sig2,
		NAT:     3,
		LocalIP: "0.0.0.0",
		IPDeny:  "no",
	})
	fmt.Printf("U_QRY text:\n%s\n", req)
	if err := sess.Send([]byte(req)); err != nil {
		fmt.Println("send:", err)
		return
	}
	resp, err := sess.Recv()
	if err != nil {
		fmt.Println("recv:", err)
		return
	}
	fmt.Printf("response (%dB):\n%s\n", len(resp), resp)

	r := p2p.ParseResponse(string(resp))
	switch {
	case r.Denied:
		fmt.Println("result: DENY_IP")
	case r.ResourceDel:
		fmt.Println("result: RES_DEL")
	default:
		fmt.Printf("result: ver=%s searchtm=%d filelen=%d peers=%d urls=%d\n",
			r.FormatVer, r.SearchTM, r.FileLen, len(r.Peers), len(r.URLs))
		for _, u := range r.URLs {
			fmt.Println("  URL:", u)
		}
		for _, p := range r.Peers {
			fmt.Printf("  PEER kid=%d %s:%d flags=%d,%d,%d idx=%d\n",
				p.Kid, p.IP, p.Port, p.Flag1, p.Flag2, p.Flag3, p.Index)
		}
	}
}

func mustAtoi(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		panic(err)
	}
	return n
}
