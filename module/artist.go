package module

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"kuwoapi/util"
)

// Artist 歌手分类/歌手页
// 来源：channel_artist.js + content_artist.js
// 端点族：
//   歌手列表   http://artistlistinfo.kuwo.cn/mb.slist?stype=artistlist&category=&order=hot&prefix=&pn=&rn=
//   歌手信息   http://search.kuwo.cn/r.s?stype=artistinfo&artistid=
//   歌手歌曲   http://search.kuwo.cn/r.s?stype=artist2music&artistid=&pn=&rn=&sortby=
//   歌手专辑   http://search.kuwo.cn/r.s?stype=albumlist&artistid=&pn=&rn=&sortby=
//   歌手MV     http://search.kuwo.cn/r.s?stype=mvlist&artistid=&pn=&rn=&sortby=
func Artist(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	action := util.GetString(params, "action", "list")
	client := &http.Client{Timeout: 10 * time.Second}

	var u string
	switch action {
	case "list":
		category := util.GetInt(params, "category", 1)
		order := util.GetString(params, "order", "hot")
		prefix := util.GetString(params, "prefix", "")
		if prefix == "#" {
			prefix = "%23"
		}
		u = fmt.Sprintf("http://artistlistinfo.kuwo.cn/mb.slist?stype=artistlist&category=%d&order=%s&prefix=%s&pn=%d&rn=%d&encoding=utf8",
			category, order, prefix, util.GetInt(params, "pn", 0), util.GetInt(params, "rn", 60))

	case "info":
		u = fmt.Sprintf("http://search.kuwo.cn/r.s?stype=artistinfo&artistid=%s&encoding=utf8",
			util.GetString(params, "artistid", ""))
	case "songs":
		u = fmt.Sprintf("http://search.kuwo.cn/r.s?stype=artist2music&artistid=%s&pn=%d&rn=%d&sortby=%s&show_copyright_off=1&encoding=utf8",
			util.GetString(params, "artistid", ""), util.GetInt(params, "pn", 0), util.GetInt(params, "rn", 30),
			util.GetString(params, "sortby", "0"))
	case "albums":
		u = fmt.Sprintf("http://search.kuwo.cn/r.s?stype=albumlist&artistid=%s&pn=%d&rn=%d&sortby=1&show_copyright_off=1&encoding=utf8",
			util.GetString(params, "artistid", ""), util.GetInt(params, "pn", 0), util.GetInt(params, "rn", 10))
	case "mvs":
		u = fmt.Sprintf("http://search.kuwo.cn/r.s?stype=mvlist&artistid=%s&pn=%d&rn=%d&sortby=1&show_copyright_off=1&encoding=utf8",
			util.GetString(params, "artistid", ""), util.GetInt(params, "pn", 0), util.GetInt(params, "rn", 8))
	default:
		return map[string]interface{}{"code": 400, "msg": "action 仅支持 list/info/songs/albums/mvs"}, nil
	}

	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	out := map[string]interface{}{"code": 200, "action": action}

	// r.s / mb.slist 返回 Python 风格单引号 JSON
	if strings.HasPrefix(strings.TrimSpace(text), "{") || strings.HasPrefix(strings.TrimSpace(text), "[") {
		std := singleQuoteToJSON(text)
		var v interface{}
		if err := json.Unmarshal([]byte(std), &v); err == nil {
			out["data"] = v
			return out, nil
		}
	}
	out["raw"] = text
	return out, nil
}

// singleQuoteToJSON 将酷我 r.s 的 {'k':'v'} 风格转为标准 JSON
func singleQuoteToJSON(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 16)
	inStr := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'' && !inStr:
			inStr = true
			b.WriteByte('"')
		case c == '\'' && inStr:
			inStr = false
			b.WriteByte('"')
		case c == '"' && inStr:
			b.WriteString(`\"`)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
