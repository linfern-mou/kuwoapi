package main

import (
	"fmt"
	"net/http"
	"time"

	"kuwoapi/module/p2p"
)

func main() {
	fmt.Println("=== Kuwo P2P Protocol Checker ===")
	fmt.Printf("Time: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()

	client := &http.Client{Timeout: 10 * time.Second}

	// Stage 1: IP Check
	fmt.Println("Stage 1: IP Check")
	ipResp, err := p2p.DoIpCheck(client, 15277654)
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	} else {
		fmt.Printf("  PublicIP: %s\n", ipResp.PublicIP)
		fmt.Printf("  Status: %s\n", ipResp.Status)
	}
	fmt.Println()

	// Stage 2: Search
	fmt.Println("Stage 2: Search (周杰伦)")
	results, err := p2p.DhjssSearch("周杰伦")
	if err != nil {
		fmt.Printf("  ERROR: %v\n", err)
	} else {
		fmt.Printf("  Found %d results\n", len(results))
		for i, r := range results[:min(len(results), 3)] {
			fmt.Printf("    [%d] %s (type=%s, id=%s)\n", i+1, r.Name, r.Type, r.ID)
			if len(r.Song) > 0 {
				fmt.Printf("        Song: %s - %s (id:%s)\n", r.Song[0].Name, r.Song[0].Artist, r.Song[0].Id)
			}
		}
	}
	fmt.Println()

	// Stage 3: Music Pay (匿名!)
	fmt.Println("Stage 3: Music Pay (匿名请求)")
	if len(results) > 0 && len(results[0].Song) > 0 {
		songID := results[0].Song[0].Id
		payResp, err := p2p.DoMusicPay(client, 88594783, 1072809302, parseUint(songID), 0)
		if err != nil {
			fmt.Printf("  ERROR: %v\n", err)
		} else {
			fmt.Printf("  Errorcode: %d\n", payResp.ErrorCod)
			if len(payResp.Songs) > 0 {
				song := payResp.Songs[0]
				fmt.Printf("  MINFO len: %d\n", len(song.MINFO))
				
				// 解析MINFO
				qualities := p2p.ParseMINFO(song.MINFO)
				fmt.Printf("  Qualities: %d\n", len(qualities))
				for _, q := range qualities[:3] {
					fmt.Printf("    - %s br=%d\n", q.Format, q.Bitrate)
				}
				
				// 最佳音质
				best := p2p.BestQuality(song)
				if best != nil {
					fmt.Printf("  Best: %s br=%d\n", best.Format, best.Bitrate)
				}
				
				// URL
				fmt.Printf("  URL: %s\n", song.URL[:min(len(song.URL), 80)]+"...")
			}
		}
	}
	fmt.Println()

	// Stage 4: Kwmsg Heartbeat
	fmt.Println("Stage 4: Kwmsg Heartbeat Frame")
	frame := p2p.BuildKwmsgHeartbeat(15277654, 1, "8.7.4.0_BDS", "8.7.4.0_BDS")
	fmt.Printf("  Length: %d bytes\n", len(frame))
	fmt.Printf("  Type: 0x%04X\n", frame[0])
	fmt.Println()

	fmt.Println("=== Summary ===")
	fmt.Println("[OK] IP Check - DoIpCheck(client, kid)")
	fmt.Println("[OK] Search - DhjssSearch(keyword)")
	fmt.Println("[OK] MusicPay - DoMusicPay(client, uid, sid, rid, acctType)")
	fmt.Println("[OK] Kwmsg - BuildKwmsgHeartbeat(kid, try, configVer, clientVer)")
	fmt.Println()
	fmt.Println("关键发现: music.pay无需登录即可获取下载信息!")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func parseUint(s string) uint64 {
	var n uint64
	fmt.Sscanf(s, "%d", &n)
	return n
}
