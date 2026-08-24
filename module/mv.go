package module

import (
	"fmt"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"kuwoapi/util"
)

// MV 频道
// 来源：content_mv.js / content_artist.js
// 注：老频道首页 album.kuwo.cn/album/mv2015 已 302 下线；歌手维度 mvlist 存活。
//   歌手MV列表 http://search.kuwo.cn/r.s?stype=mvlist&artistid=&pn=&rn=&sortby=1
func MV(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	artistid := util.GetString(params, "artistid", "")
	if artistid == "" {
		return map[string]interface{}{"code": 400, "msg": "缺少参数 artistid(可用 /artist?action=list 获取)"}, nil
	}
	u := fmt.Sprintf("http://search.kuwo.cn/r.s?stype=mvlist&artistid=%s&pn=%d&rn=%d&sortby=%s&show_copyright_off=1&encoding=utf8",
		artistid, util.GetInt(params, "pn", 0), util.GetInt(params, "rn", 20),
		util.GetString(params, "sortby", "1"))

	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	text := string(body)

	out := map[string]interface{}{"code": 200}
	if strings.HasPrefix(strings.TrimSpace(text), "{") {
		var v interface{}
		if err := jsonUnmarshalSingleQuote(text, &v); err == nil {
			out["data"] = v
			return out, nil
		}
	}
	out["raw"] = text
	return out, nil
}

// jsonUnmarshalSingleQuote 解析酷我 r.s 单引号 JSON
func jsonUnmarshalSingleQuote(s string, v interface{}) error {
	return json.Unmarshal([]byte(singleQuoteToJSON(s)), v)
}
