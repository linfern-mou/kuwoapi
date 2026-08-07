package module

import (
	"fmt"
	"io"
	"net/http"
	"kuwoapi/util"
)

// Lyric 歌词接口
// 来源：KwModLyric.dll strings
// URL模板：http://newlyric.kuwo.cn/newlyric.lrc?musicId=%s&lrcx=1&contenttype=zip&olrc=1
// 响应格式：zip压缩的歌词文件（.lrc / .lrcx）
func Lyric(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	rid := util.GetString(params, "id", "")
	if rid == "" {
		return map[string]interface{}{"code": 400, "msg": "缺少参数 id"}, nil
	}

	// URL 来源：KwModLyric.dll strings
	// http://newlyric.kuwo.cn/newlyric.lrc?musicId=%s&lrcx=1&contenttype=zip&olrc=1&requester=localhost&type=sim
	u := fmt.Sprintf("http://newlyric.kuwo.cn/newlyric.lrc?musicId=%s&lrcx=1&contenttype=zip&olrc=1&requester=localhost&type=sim", rid)

	req, _ := http.NewRequest("GET", u, nil)
	// 请求头来源：KwHttpRequestMgr.dll strings
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/534.10 (KHTML, like Gecko) Chrome/8.0.552.215 Safari/534.10")
	req.Header.Set("Accept", "application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.8")
	req.Header.Set("Accept-Charset", "GBK,utf-8;q=0.7,*;q=0.3")
	req.Header.Set("Accept-encoding", "gzip, deflate")
	req.Header.Set("Connection", "Close")

	resp, err := util.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("歌词请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// 响应格式：zip压缩的歌词文件
	// 来源：KwModLyric.dll strings - &contenttype=zip, .lrc, .lrcx
	return map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"rid":   rid,
			"lyric": body,
		},
	}, nil
}
