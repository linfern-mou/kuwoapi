package module

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"kuwoapi/util"
)

// Search 搜索接口（APK 版）
// 来源：酷我 Android 客户端（kuwoapk 分支）
// URL模板：http://search.kuwo.cn/r.s?client=kt&all=%s&pn=%d&rn=%d&ft=music&cluster=0&strategy=2012&ver=mbox&show_copyright_off=1&encoding=utf8&rformat=json&mobi=1&vipver=1&issubtitle=1&correct=1&newver=1&vermerge=1&srcfrom=preference_bl
// 响应格式：JSON（rformat=json），顶层含 TOTAL/SHOW/PN/RN/HIT/abslist/searchgroup
func Search(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	key := util.GetString(params, "key", "")
	if key == "" {
		return map[string]interface{}{"code": 400, "msg": "缺少参数 key"}, nil
	}

	pn := util.GetInt(params, "pn", 0)
	rn := util.GetInt(params, "rn", 25)

	// URL 来源：kuwoapk（酷我 Android 客户端搜索请求）
	u := fmt.Sprintf("http://search.kuwo.cn/r.s?client=kt&all=%s&pn=%d&rn=%d&ft=music&cluster=0&strategy=2012&ver=mbox&show_copyright_off=1&encoding=utf8&rformat=json&mobi=1&vipver=1&issubtitle=1&correct=1&newver=1&vermerge=1&srcfrom=preference_bl",
		url.QueryEscape(key), pn, rn)

	req, _ := http.NewRequest("GET", u, nil)
	// 请求头来源：kuwoapk（酷我 Android 客户端）
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("搜索请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 响应格式：JSON（rformat=json）
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return map[string]interface{}{"code": 200, "data": string(body)}, nil
	}

	songs := parseAbslist(raw)

	return map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"total": util.GetInt(raw, "TOTAL", 0),
			"show":  util.GetInt(raw, "SHOW", 0),
			"pn":    util.GetInt(raw, "PN", pn),
			"rn":    util.GetInt(raw, "RN", rn),
			"hit":   util.GetInt(raw, "HIT", 0),
			"songs": songs,
		},
	}, nil
}

// parseAbslist 解析 APK 搜索响应中的 abslist 歌曲数组
// 字段来源：kuwoapk（酷我 Android 客户端 JSON 响应）
func parseAbslist(raw map[string]interface{}) []map[string]interface{} {
	var songs []map[string]interface{}

	abs, ok := raw["abslist"].([]interface{})
	if !ok {
		return songs
	}

	for _, item := range abs {
		m, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		song := map[string]interface{}{
			"rid":       util.GetString(m, "MUSICRID", ""),
			"name":      firstNonEmpty(util.GetString(m, "SONGNAME", ""), util.GetString(m, "NAME", "")),
			"artist":    util.GetString(m, "ARTIST", ""),
			"artistid":  util.GetString(m, "ARTISTID", ""),
			"album":     util.GetString(m, "ALBUM", ""),
			"albumid":   util.GetString(m, "ALBUMID", ""),
			"duration":  util.GetString(m, "DURATION", ""),
			"format":    util.GetString(m, "FORMAT", ""),
			"mvflag":    util.GetString(m, "MVFLAG", ""),
			"mvquality": util.GetString(m, "MVQUALITY", ""),
			"mvpic":     util.GetString(m, "MVPIC", ""),
			"pay":       util.GetString(m, "PAY", ""),
			"subtitle":  util.GetString(m, "SUBTITLE", ""),
			"minfo":     util.GetString(m, "MINFO", ""),
			"n_minfo":   util.GetString(m, "N_MINFO", ""),
			"online":    util.GetString(m, "ONLINE", ""),
		}
		// 保留 APK 原始字段，便于调用方直接使用
		song["raw"] = m

		songs = append(songs, song)
	}

	return songs
}

// firstNonEmpty 返回第一个非空字符串
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
