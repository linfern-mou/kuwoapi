package p2p

import (
	"net"
	"os"
	"testing"
)

func TestXorYeelion(t *testing.T) {
	got := xorYeelion([]byte("serverlist"))
	want := []byte{0x0a, 0x00, 0x17, 0x1a, 0x0c, 0x1d, 0x02, 0x49, 0x0a, 0x11}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("xor mismatch at %d: got %x want %x", i, got, want)
		}
	}
}

func TestBuildConfigURL(t *testing.T) {
	url := BuildConfigURL("15277654", "MUSIC_8.7.4.0_BDS1", "kwmusic_web_1_bds_20171206")
	const prefix = "http://config.kuwo.cn/uc/s?m=61;"
	if len(url) < len(prefix) || url[:len(prefix)] != prefix {
		t.Fatalf("unexpected URL: %s", url)
	}
}

func TestINIGetAndServers(t *testing.T) {
	ini := "[p2p]\nclosehttp=1\nHeartbeatServer=175.102.178.96:25607,175.102.178.97:25607\n[ResSearch]\nResServCnt=2\nSearchServer1=664566069\nSearchServer2=664566562\n"
	hb := HeartbeatServersFromConfig(ini)
	if len(hb) != 2 || hb[0] != "175.102.178.96:25607" {
		t.Fatalf("hb parse: %v", hb)
	}
	ss := SearchServersFromConfig(ini)
	want1 := "39.156.121.53"
	if len(ss) != 2 || ss[0] != want1 || ss[1] != "39.156.123.34" {
		t.Fatalf("search parse: %v", ss)
	}
	if net.ParseIP(want1) == nil {
		t.Fatalf("bad ip %s", want1)
	}
}

// Live test: opt-in via KUWO_CONFIG_LIVE=1.
func TestFetchServerConfigLive(t *testing.T) {
	if os.Getenv("KUWO_CONFIG_LIVE") == "" {
		t.Skip("live test disabled (set KUWO_CONFIG_LIVE=1)")
	}
	ini, err := FetchServerConfig("15277654")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	t.Logf("ini %d bytes", len(ini))
	if hb := HeartbeatServersFromConfig(ini); len(hb) > 0 {
		t.Logf("HeartbeatServer: %v", hb)
	} else {
		t.Errorf("no HeartbeatServer in response")
	}
	if ss := SearchServersFromConfig(ini); len(ss) > 0 {
		t.Logf("SearchServers: %v", ss)
	}
}
