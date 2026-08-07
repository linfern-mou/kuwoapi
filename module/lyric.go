package module

import (
	"fmt"
	"io"
	"net/http"
	"kuwoapi/util"
)

// Lyric 歌词接口
// 来源：KwModLyric.dll strings
// 端点：http://newlyric.kuwo.cn/newlyric.lrc
func Lyric(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	rid := util.GetString(params, "id", "")
	if rid == "" {
		return map[string]interface{}{"code": 400, "msg": "缺少参数 id"}, nil
	}

	u := fmt.Sprintf("http://newlyric.kuwo.cn/newlyric.lrc?musicId=%s&lrcx=1&contenttype=zip&olrc=1", rid)
	resp, err := util.HTTPClient.Get(u)
	if err != nil {
		return nil, fmt.Errorf("歌词请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"code": 200,
		"data": map[string]interface{}{
			"rid":   rid,
			"lyric": string(body),
		},
	}, nil
}
