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

// Rcm 每日推荐/个性化推荐
// 来源：content_rcm.js
// 端点族：
//   发现页推荐(新) http://nmobi.kuwo.cn/mobi.s?f=web&q=12345&type=rcm_discover&uid=&devid=&platform=pc&pn=&rn=
//   私人推荐       http://rcm.kuwo.cn/rec.s?cmd=rcm_personal&uid=&devid=&platform=pc&pn=&rn=
//   口味模块       http://rcm.kuwo.cn/rec.s?cmd=rcm_taste_module&uid=&devid=&platform=pc&pn=&rn=
//   听歌历史       http://rcm.kuwo.cn/rec.s?cmd=rcm_listen_history&uid=&devid=&platform=pc
func Rcm(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	cmd := util.GetString(params, "cmd", "discover")
	uid := util.GetString(params, "uid", "0")
	devid := util.GetString(params, "devid", "43513807")
	pn := util.GetInt(params, "pn", 0)
	rn := util.GetInt(params, "rn", 30)

	var u string
	switch cmd {
	case "discover":
		u = fmt.Sprintf("http://nmobi.kuwo.cn/mobi.s?f=web&q=12345&type=rcm_discover&uid=%s&devid=%s&platform=pc&pn=%d&rn=%d",
			uid, devid, pn, rn)
	case "personal":
		u = fmt.Sprintf("http://rcm.kuwo.cn/rec.s?cmd=rcm_personal&uid=%s&devid=%s&platform=pc&pn=%d&rn=%d",
			uid, devid, pn, rn)
	case "taste":
		u = fmt.Sprintf("http://rcm.kuwo.cn/rec.s?cmd=rcm_taste_module&uid=%s&devid=%s&platform=pc&pn=%d&rn=%d",
			uid, devid, pn, rn)
	case "history":
		u = fmt.Sprintf("http://rcm.kuwo.cn/rec.s?cmd=rcm_listen_history&uid=%s&devid=%s&platform=pc", uid, devid)
	default:
		return map[string]interface{}{"code": 400, "msg": "cmd 仅支持 discover/personal/taste/history"}, nil
	}

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

	if strings.HasPrefix(text, "[") {
		songs := parseRcmJSON(text)
		mergeRcmParams(songs)
		return map[string]interface{}{"code": 200, "cmd": cmd, "data": songs}, nil
	}
	if cmd == "taste" && strings.HasPrefix(text, "{") {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(text), &obj); err == nil {
			if taste, ok := obj["taste"].([]interface{}); ok {
				mergeRcmParams(taste)
			}
			return map[string]interface{}{"code": 200, "cmd": cmd, "data": obj}, nil
		}
	}
	return map[string]interface{}{"code": 200, "cmd": cmd, "raw": text}, nil
}

// mergeRcmParams 将每首歌的 params 签名链解析并入
func mergeRcmParams(songs []interface{}) {
	for _, s := range songs {
		if m, ok := s.(map[string]interface{}); ok {
			if chain, _ := m["params"].(string); chain != "" {
				mergeParam(m, chain)
			}
		}
	}
}

// parseRcmJSON 解析 rec.s/mobi.s 返回的歌曲 JSON 数组
func parseRcmJSON(text string) []interface{} {
	var out []interface{}
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		return nil
	}
	return out
}
