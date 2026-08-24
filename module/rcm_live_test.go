package module

import (
	"testing"
)

func TestRcmLive(t *testing.T) {
	for _, cmd := range []string{"discover", "personal", "taste"} {
		out, err := Rcm(map[string]interface{}{"cmd": cmd, "rn": 3}, nil)
		if err != nil {
			t.Errorf("%s: %v", cmd, err)
			continue
		}
		if data, ok := out["data"].([]interface{}); ok && len(data) > 0 {
			first := data[0].(map[string]interface{})
			t.Logf("%s: %d songs, first=%v rid=%v nsig=(%v,%v)", cmd, len(data),
				first["name"], first["musicrid"], first["nsig1"], first["nsig2"])
		} else {
			t.Logf("%s: raw=%v", cmd, out["raw"])
		}
	}
}

func TestRadioLive(t *testing.T) {
	tree, err := Radio(map[string]interface{}{"action": "tree"}, nil)
	if err != nil {
		t.Fatalf("tree: %v", err)
	}
	t.Logf("tree ok, has data=%v", tree["data"] != nil)

	songs, err := Radio(map[string]interface{}{"action": "songs", "fid": "-26711"}, nil)
	if err != nil {
		t.Fatalf("songs: %v", err)
	}
	if data, ok := songs["data"].([]map[string]interface{}); ok && len(data) > 0 {
		first := data[0]
		t.Logf("songs: %d, first=%v - %v sig=(%v,%v)", len(data),
			first["artist"], first["name"], first["nsig1"], first["nsig2"])
	} else {
		t.Logf("songs raw: %v", songs["raw"])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestArtistLive(t *testing.T) {
	list, err := Artist(map[string]interface{}{"action": "list", "category": 1, "rn": 3}, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	t.Logf("list ok, data=%v", list["data"] != nil)

	songs, err := Artist(map[string]interface{}{"action": "songs", "artistid": "336", "rn": 2}, nil)
	if err != nil {
		t.Fatalf("songs: %v", err)
	}
	if d, ok := songs["data"].(map[string]interface{}); ok {
		ml := d["musiclist"].([]interface{})
		first := ml[0].(map[string]interface{})
		t.Logf("songs: %d first=%v", len(ml), first["name"] != nil || first["SONGNAME"] != nil)
	} else {
		t.Logf("songs raw: %.150s", songs["raw"])
	}

	info, err := Artist(map[string]interface{}{"action": "info", "artistid": "336"}, nil)
	if err != nil {
		t.Fatalf("info: %v", err)
	}
	t.Logf("info ok, data=%v", info["data"] != nil)
}
