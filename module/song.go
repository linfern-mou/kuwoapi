package module

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"kuwoapi/util"
)

// SongURL 歌曲播放地址接口（APK 版）
// 来源：酷我 Android 客户端（kuwoapk 分支）
// URL模板：http://antiserver.kuwo.cn/anti.s?type=convert_url&rid=%s&format=%s
// 响应格式：纯文本，返回真实音频直链（mp3/aac）；flac/ape 返回 "refuse request!"
func SongURL(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	rid := util.GetString(params, "id", "")
	if rid == "" {
		return map[string]interface{}{"code": 400, "msg": "缺少参数 id"}, nil
	}

	format := util.GetString(params, "format", "mp3")

	ids := rid
	if !strings.HasPrefix(rid, "MUSIC_") {
		ids = "MUSIC_" + rid
	}

	// URL 来源：kuwoapk（酷我 Android 客户端 antiserver 反盗链转换）
	u := fmt.Sprintf("http://antiserver.kuwo.cn/anti.s?type=convert_url&rid=%s&format=%s", url.QueryEscape(ids), url.QueryEscape(format))

	req, _ := http.NewRequest("GET", u, nil)
	// 请求头来源：kuwoapk（酷我 Android 客户端）
	req.Header.Set("User-Agent", "Mozilla/5.0 (Linux; Android 14; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Mobile Safari/537.36")
	req.Header.Set("Referer", "http://www.kuwo.cn/")

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("播放地址请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	playURL := strings.TrimSpace(string(body))

	// 非 mp3/aac 格式或请求被拒时返回错误
	if playURL == "" || strings.Contains(playURL, "refuse") {
		return map[string]interface{}{"code": 200, "data": map[string]interface{}{
			"rid":    ids,
			"format": format,
			"url":    "",
			"msg":    "该格式不可用（可能需 VIP），请使用 mp3/aac",
		}}, nil
	}

	return map[string]interface{}{"code": 200, "data": map[string]interface{}{
		"rid":    ids,
		"format": format,
		"url":    playURL,
	}}, nil
}

// SongDetail 歌曲详情（与 SongURL 相同）
func SongDetail(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	return SongURL(params, r)
}
