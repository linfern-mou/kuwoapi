package module

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"kuwoapi/module/p2p"
)

// TestLiveRankSig 验证榜单接口返回的 sig 对可直接用于 P2P 查询链路。
// 步骤：热歌榜取歌 -> param 链 nsig1/nsig2 -> rid.kuwo.cn/sig.s 对照 -> U_QRY 实发。
func TestLiveRankSig(t *testing.T) {
	data, err := Rank(map[string]interface{}{"id": "16", "rn": 5}, nil)
	if err != nil {
		t.Fatalf("rank: %v", err)
	}
	d, _ := data["data"].(map[string]interface{})
	ml, _ := d["musiclist"].([]interface{})
	if len(ml) == 0 {
		t.Fatal("empty musiclist")
	}
	m, _ := ml[0].(map[string]interface{})

	name, _ := m["name"].(string)
	musicrid, _ := m["musicrid"].(string)
	nsig1 := fmt.Sprintf("%v", m["nsig1"])
	nsig2 := fmt.Sprintf("%v", m["nsig2"])
	t.Logf("song=%q musicrid=%s nsig1=%s nsig2=%s", name, musicrid, nsig1, nsig2)

	rid := strings.TrimPrefix(musicrid, "MUSIC_")

	sig1, err1 := strconv.ParseUint(nsig1, 10, 32)
	sig2, err2 := strconv.ParseUint(nsig2, 10, 32)
	if err1 != nil || err2 != nil {
		t.Fatalf("bad sig: %v %v", err1, err2)
	}

	refreshed1, refreshed2, err := refreshSig(rid)
	t.Logf("refreshSig(%s) = (%s,%s) err=%v match=%v", rid, refreshed1, refreshed2, err,
		refreshed1 == nsig1 && refreshed2 == nsig2)

	q := p2p.QueryParams{
		UID:     15277654,
		Sig1:    uint32(sig1),
		Sig2:    uint32(sig2),
		NAT:     3,
		LocalIP: "192.168.1.100",
		IPDeny:  "no",
	}
	text := p2p.BuildUQRY(q)
	req := "GET /yl_res_manage.search?" + text + " HTTP/1.0\r\n" +
		"Host: deliver.kuwo.cn\r\n" +
		"User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)\r\n" +
		"Accept: */*\r\n" +
		"Accept-Encoding: gzip, deflate\r\n" +
		"Connection: Close\r\n\r\n"

	c := &http.Client{Timeout: 15 * time.Second}
	resp, err := c.Post("http://deliver.kuwo.cn/yl_res_manage.search", "text/plain", strings.NewReader(text))
	if err != nil {
		t.Logf("POST failed: %v", err)
	} else {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Logf("POST status=%d body=%q", resp.StatusCode, string(b))
	}

	conn, err := net.DialTimeout("tcp", "deliver.kuwo.cn:80", 10*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	conn.Write([]byte(req))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	t.Logf("RAW GET resp:\n%s", string(buf[:n]))

	if n > 0 && strings.Contains(string(buf[:n]), "PEERS") {
		t.Logf("LIVE QUERY SUCCESS with rank sig")
	}
}
