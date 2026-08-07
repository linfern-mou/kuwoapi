package module

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"net/http"
	"strings"
	"kuwoapi/util"
)

// SongURL 歌曲元数据接口
// 来源：config.ini [serverlist] SecondSearch
func SongURL(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	rid := util.GetString(params, "id", "")
	if rid == "" {
		return map[string]interface{}{"code": 400, "msg": "缺少参数 id"}, nil
	}

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
		return map[string]interface{}{"code": 200, "data": map[string]interface{}{"rid": rid, "qualities": map[string]interface{}{}}}, nil
	}

	reader, err := zlib.NewReader(bytes.NewReader(body[8:]))
	if err != nil {
		return nil, err
	}
	defer reader.Close()

	text, _ := io.ReadAll(reader)
	result := map[string]interface{}{"rid": rid, "formats": []string{}, "qualities": map[string]interface{}{}}
	qualities := map[string]interface{}{}

	for _, line := range strings.Split(string(text), "\n") {
		line = strings.TrimSpace(line)
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])

		if key == "MUSICRID" {
			result["musicrid"] = val
		} else if key == "FORMATS" {
			result["formats"] = strings.Split(val, "|")
		} else if key == "TAG" || key == "MVPROVIDER" {
			// skip
		} else {
			q := map[string]interface{}{"code": key}
			for _, p := range strings.Split(val, "|") {
				ci := strings.Index(p, ":")
				if ci < 0 {
					continue
				}
				k := strings.TrimSpace(p[:ci])
				v := strings.TrimSpace(p[ci+1:])
				switch k {
				case "S1":
					q["sig1"] = v
				case "S2":
					q["sig2"] = v
				case "SIZE":
					var n int
					fmt.Sscanf(v, "%d", &n)
					q["filesize"] = n
				case "BT":
					var n int
					fmt.Sscanf(v, "%d", &n)
					q["bitrate"] = n
				}
			}
			if _, ok := q["sig1"]; ok {
				qualities[key] = q
			}
		}
	}

	result["qualities"] = qualities
	return map[string]interface{}{"code": 200, "data": result}, nil
}

// SongDetail 歌曲详情（与 SongURL 相同）
func SongDetail(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	return SongURL(params, r)
}
