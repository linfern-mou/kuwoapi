package module

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"kuwoapi/util"
)

// 新歌速递
// 来源：content_latest.js / index.js
//   专辑/_mv 每日推荐: http://js01.kuwo.cn/star/MusicTopToday/js01/topmusic/recAlbum.js / recMv.js
//     内容为 JSONP 包装: try{var jsondata={...}}catch(e){}
//   「每日最新单曲」入口为固定歌单 id=1082685104 (index.js new_song_sourceid)
func Newest(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	switch util.GetString(params, "source", "album") {
	case "mv":
		return newestFetch("recMv.js")
	case "playlist":
		return PlaylistInfo(map[string]interface{}{
			"id": util.GetString(params, "id", "1082685104"),
			"pn": params["pn"], "rn": params["rn"],
		}, r)
	default:
		return newestFetch("recAlbum.js")
	}
}

func newestFetch(name string) (map[string]interface{}, error) {
	u := "http://js01.kuwo.cn/star/MusicTopToday/js01/topmusic/" + name
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	out := map[string]interface{}{"code": 200}
	if v, ok := extractJsVar(string(body), "jsondata"); ok {
		out["data"] = v
		return out, nil
	}
	out["raw"] = string(body)
	return out, nil
}

// extractJsVar 提取 try{var <name>={...} JSONP 包装中的对象
func extractJsVar(text, name string) (interface{}, bool) {
	marker := "var " + name + "="
	i := strings.Index(text, marker)
	if i < 0 {
		return nil, false
	}
	start := strings.Index(text[i:], "{")
	if start < 0 {
		return nil, false
	}
	start += i
	// 大括号配对扫描，跳过字符串字面量
	depth, inStr, esc := 0, false, false
	end := -1
	for j := start; j < len(text); j++ {
		c := text[j]
		if esc {
			esc = false
			continue
		}
		switch {
		case inStr:
			if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
		case c == '"':
			inStr = true
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				end = j
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return nil, false
	}
	var v interface{}
	if err := json.Unmarshal([]byte(text[start:end+1]), &v); err != nil {
		if err := jsonUnmarshalSingleQuote(text[start:end+1], &v); err != nil {
			return nil, false
		}
	}
	return v, true
}
