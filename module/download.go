package module

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"time"
	"kuwoapi/util"
)

// SongMeta 歌曲元数据
type SongMeta struct {
	RID      string
	Sig1     string
	Sig2     string
	FileSize int
	Bitrate  int
	Quality  string
}

// Download 下载接口
// 完整流程：获取元数据 → 刷新签名 → P2P 下载 → CDN 回退
func Download(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	rid := util.GetString(params, "id", "")
	if rid == "" {
		return map[string]interface{}{"code": 400, "msg": "缺少参数 id"}, nil
	}
	quality := util.GetString(params, "quality", "MP3128")

	log.Printf("[DOWN] 开始下载 rid=%s quality=%s", rid, quality)

	// Step 1: 获取元数据
	meta, err := getSongMeta(rid, quality)
	if err != nil {
		return map[string]interface{}{"code": 500, "msg": fmt.Sprintf("获取元数据失败: %v", err)}, nil
	}
	log.Printf("[DOWN] 元数据: sig1=%s sig2=%s filesize=%d", meta.Sig1, meta.Sig2, meta.FileSize)

	// Step 2: 刷新签名
	newSig1, newSig2, err := refreshSig(rid)
	if err == nil && newSig1 != "" {
		meta.Sig1 = newSig1
		meta.Sig2 = newSig2
		log.Printf("[DOWN] 签名已刷新: sig1=%s sig2=%s", newSig1, newSig2)
	} else {
		log.Printf("[DOWN] 签名刷新失败(使用原始): %v", err)
	}

	var sig1, sig2 uint32
	fmt.Sscanf(meta.Sig1, "%d", &sig1)
	fmt.Sscanf(meta.Sig2, "%d", &sig2)

	// Step 3: P2P 下载
	log.Printf("[DOWN] Step3: P2P 下载...")
	downloader := NewP2PDownloader()
	defer downloader.Close()

	if err := downloader.ConnectTracker("deliver.kuwo.cn", 25607); err != nil {
		log.Printf("[DOWN] Tracker 连接失败: %v", err)
	} else {
		log.Printf("[DOWN] Tracker 已连接")
		peers, err := downloader.SearchResource(rid, sig1, sig2)
		if err != nil {
			log.Printf("[DOWN] 搜索失败: %v", err)
		} else {
			log.Printf("[DOWN] 找到 %d 个 Peer", len(peers))
			for i, peer := range peers {
				log.Printf("[DOWN] 尝试 Peer[%d]: %s:%d", i, peer.IP, peer.Port)
				data, err := downloader.DownloadFromPeer(peer, rid, sig1, sig2)
				if err == nil && len(data) > 1000 && isValidAudio(data) {
					log.Printf("[DOWN] P2P 下载成功: %d bytes", len(data))
					return map[string]interface{}{
						"code": 200,
						"data": map[string]interface{}{
							"rid":     rid,
							"quality": quality,
							"size":    len(data),
							"sig1":    meta.Sig1,
							"sig2":    meta.Sig2,
							"data":    data,
						},
					}, nil
				}
				log.Printf("[DOWN] Peer[%d] 下载失败: %v", i, err)
			}
		}
	}

	// Step 4: CDN 回退
	log.Printf("[DOWN] Step4: CDN 回退...")
	cdnHosts := []string{
		"win.player.ra01.sycdn.kuwo.cn",
		"win.player.ra05.sycdn.kuwo.cn",
		"win.player.rc01.sycdn.kuwo.cn",
		"win.player.rc05.sycdn.kuwo.cn",
		"win.player.rg03.sycdn.kuwo.cn",
		"win.player.rg05.sycdn.kuwo.cn",
		"win.player.rh03.sycdn.kuwo.cn",
		"win.player.rh05.sycdn.kuwo.cn",
		"win.player.ri03.sycdn.kuwo.cn",
		"win.player.ri05.sycdn.kuwo.cn",
	}

	numericRID := strings.TrimPrefix(rid, "MUSIC_")
	for _, host := range cdnHosts {
		cdnURL := fmt.Sprintf("http://%s/resource/n2/11/64/%s.mp3", host, numericRID)
		client := &http.Client{Timeout: 30 * time.Second}
		resp, err := client.Get(cdnURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			continue
		}
		data, err := io.ReadAll(resp.Body)
		if err == nil && len(data) > 1000 && isValidAudio(data) {
			log.Printf("[DOWN] CDN 下载成功: %d bytes", len(data))
			return map[string]interface{}{
				"code": 200,
				"data": map[string]interface{}{
					"rid":     rid,
					"quality": quality,
					"size":    len(data),
					"data":    data,
				},
			}, nil
		}
	}

	return map[string]interface{}{"code": 500, "msg": "所有下载方式均失败"}, nil
}

func getSongMeta(rid, quality string) (*SongMeta, error) {
	ids := rid
	if !strings.HasPrefix(rid, "MUSIC_") {
		ids = "MUSIC_" + rid
	}

	u := fmt.Sprintf("http://search.kuwo.cn/r.s?stype=musicinfo&itemset=music_2014&alflac=1&pcmp4=1&ids=%s", ids)
	resp, err := util.HTTPClient.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if len(body) < 10 {
		return nil, fmt.Errorf("未找到歌曲元数据")
	}

	reader, err := zlib.NewReader(bytes.NewReader(body[8:]))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	text, _ := io.ReadAll(reader)
	meta := &SongMeta{RID: rid, Quality: quality}

	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if key == quality {
			for _, p := range strings.Split(val, "|") {
				ci := strings.Index(p, ":")
				if ci < 0 {
					continue
				}
				k := strings.TrimSpace(p[:ci])
				v := strings.TrimSpace(p[ci+1:])
				switch k {
				case "S1":
					meta.Sig1 = v
				case "S2":
					meta.Sig2 = v
				case "SIZE":
					fmt.Sscanf(v, "%d", &meta.FileSize)
				case "BT":
					fmt.Sscanf(v, "%d", &meta.Bitrate)
				}
			}
			break
		}
	}

	if meta.Sig1 == "" && meta.Sig2 == "" && meta.FileSize == 0 {
		return nil, fmt.Errorf("未找到音质 %s", quality)
	}
	return meta, nil
}

func refreshSig(rid string) (string, string, error) {
	u := fmt.Sprintf("http://rid.kuwo.cn/sig.s?w=%s&c=mbox", rid)
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	s := string(body)

	var sig1, sig2 string
	if idx := strings.Index(s, "sig1="); idx >= 0 {
		s2 := s[idx+5:]
		if end := strings.IndexAny(s2, " \n\r"); end >= 0 {
			sig1 = s2[:end]
		} else {
			sig1 = s2
		}
	}
	if idx := strings.Index(s, "sig2="); idx >= 0 {
		s2 := s[idx+5:]
		if end := strings.IndexAny(s2, " \n\r"); end >= 0 {
			sig2 = s2[:end]
		} else {
			sig2 = s2
		}
	}
	return sig1, sig2, nil
}

func isValidAudio(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	return (data[0] == 0xFF && (data[1]&0xE0) == 0xE0) ||
		string(data[:4]) == "fLaC" ||
		string(data[:3]) == "ID3"
}

// P2P 下载器 - 来源：KwMV.dll CSFSocket
type P2PDownloader struct {
	conn     *net.UDPConn
	seqNum   uint32
	ackNum   uint32
	peerAddr *net.UDPAddr
}

type PeerInfo struct {
	IP      string
	Port    int
	UID     uint32
	NATType int
}

func NewP2PDownloader() *P2PDownloader {
	return &P2PDownloader{seqNum: rand.Uint32()}
}

func (d *P2PDownloader) ConnectTracker(host string, port int) error {
	addr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", host, port))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return err
	}
	d.conn = conn
	d.peerAddr = addr

	// SYN
	syn := make([]byte, 19)
	syn[0] = 1 // version
	syn[2] = 1 // type SYN
	d.conn.WriteToUDP(syn, addr)

	// SYNACK
	d.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := d.conn.ReadFromUDP(buf)
	if err != nil || n < 4 || buf[2] != 2 {
		return fmt.Errorf("SYNACK 超时")
	}

	// ACK
	ack := make([]byte, 19)
	ack[0] = 1
	ack[2] = 3 // type ACK
	d.conn.WriteToUDP(ack, addr)
	return nil
}

func (d *P2PDownloader) SearchResource(rid string, sig1, sig2 uint32) ([]PeerInfo, error) {
	searchData := fmt.Sprintf("rid=%s&sig1=%d&sig2=%d", rid, sig1, sig2)
	pkt := make([]byte, 18+len(searchData))
	pkt[0] = 1
	pkt[2] = 0x10 // SEARCH
	copy(pkt[18:], searchData)
	d.conn.WriteToUDP(pkt, d.peerAddr)

	d.conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 65536)
	n, _, err := d.conn.ReadFromUDP(buf)
	if err != nil || n < 18 || buf[2] != 0x11 {
		return nil, fmt.Errorf("搜索超时")
	}

	return parsePeers(string(buf[18:n])), nil
}

func (d *P2PDownloader) DownloadFromPeer(peer PeerInfo, rid string, sig1, sig2 uint32) ([]byte, error) {
	peerAddr, err := net.ResolveUDPAddr("udp4", fmt.Sprintf("%s:%d", peer.IP, peer.Port))
	if err != nil {
		return nil, err
	}
	d.peerAddr = peerAddr

	reqData := fmt.Sprintf("rid=%s&sig1=%d&sig2=%d", rid, sig1, sig2)
	pkt := make([]byte, 18+len(reqData))
	pkt[0] = 1
	pkt[2] = 0x30 // DATA
	copy(pkt[18:], reqData)
	d.conn.WriteToUDP(pkt, peerAddr)

	var fileData []byte
	for {
		d.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		buf := make([]byte, 65536)
		n, _, err := d.conn.ReadFromUDP(buf)
		if err != nil {
			break
		}
		if n < 18 {
			continue
		}
		switch buf[2] {
		case 0x31: // DATAR
			fileData = append(fileData, buf[18:n]...)
		case 0x04: // FIN
			return fileData, nil
		}
	}
	return fileData, nil
}

func (d *P2PDownloader) Close() {
	if d.conn != nil {
		fin := make([]byte, 19)
		fin[0] = 1
		fin[2] = 4 // FIN
		d.conn.WriteToUDP(fin, d.peerAddr)
		d.conn.Close()
	}
}

func parsePeers(s string) []PeerInfo {
	var peers []PeerInfo
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ip string
		var port int
		var uid uint32
		var natType int
		n, _ := fmt.Sscanf(line, "%s %d %d %d", &ip, &port, &uid, &natType)
		if n >= 2 {
			peers = append(peers, PeerInfo{IP: ip, Port: port, UID: uid, NATType: natType})
		}
	}
	return peers
}
