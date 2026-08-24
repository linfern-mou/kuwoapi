package module

import (
	"testing"
)

func TestNewestAlbumLive(t *testing.T) {
	out, err := Newest(map[string]interface{}{}, nil)
	if err != nil {
		t.Fatalf("album: %v", err)
	}
	if out["code"] != 200 {
		t.Fatalf("album code=%v", out["code"])
	}
	if _, ok := out["data"]; !ok {
		t.Fatalf("album no data, raw=%v", out["raw"])
	}
	t.Logf("album ok")
}

func TestNewestMvLive(t *testing.T) {
	out, err := Newest(map[string]interface{}{"source": "mv"}, nil)
	if err != nil {
		t.Fatalf("mv: %v", err)
	}
	if _, ok := out["data"]; !ok {
		t.Fatalf("mv no data, raw=%v", out["raw"])
	}
	t.Logf("mv ok")
}

func TestNewestPlaylistLive(t *testing.T) {
	out, err := Newest(map[string]interface{}{"source": "playlist", "rn": 5}, nil)
	if err != nil {
		t.Fatalf("playlist: %v", err)
	}
	if out["code"] != 200 {
		t.Fatalf("playlist code=%v raw=%v", out["code"], out["raw"])
	}
	t.Logf("playlist ok")
}
