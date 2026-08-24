package module

import "testing"

func TestMVLive(t *testing.T) {
	out, err := MV(map[string]interface{}{"artistid": "336", "rn": 3}, nil)
	if err != nil {
		t.Fatalf("mv: %v", err)
	}
	if d, ok := out["data"].(map[string]interface{}); ok {
		if ml, ok := d["mvlist"].([]interface{}); ok && len(ml) > 0 {
			first := ml[0].(map[string]interface{})
			t.Logf("mvs: %d first=%v", len(ml), first["name"])
			return
		}
	}
	t.Logf("raw: %.200s", out["raw"])
}
