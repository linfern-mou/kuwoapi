package module

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"golang.org/x/text/encoding/simplifiedchinese"
	"time"

	"kuwoapi/util"
)

// Radio 私人电台/主题电台
// 来源：channel_radio.js + play_radio.js
// 端点族：
//   分类树   http://qukudata.kuwo.cn/q.k?op=query&cont=tree&node=87235&pn=0&rn=100&fmt=json&src=mbox&level=3&sourceset=tag_radio&extend=gxh
//   电台取歌 http://gxh2.kuwo.cn/newradio.nr?type=3&uid=&login=1&ver=&fid={电台ID}
func Radio(params map[string]interface{}, r *http.Request) (map[string]interface{}, error) {
	action := util.GetString(params, "action", "tree")
	uid := util.GetString(params, "uid", "0")
	ver := util.GetString(params, "ver", "8.7.4.0_BDS1")

	client := &http.Client{Timeout: 10 * time.Second}
	var u string

	switch action {
	case "tree":
		rn := util.GetInt(params, "rn", 100)
		u = fmt.Sprintf("http://qukudata.kuwo.cn/q.k?op=query&cont=tree&node=87235&pn=0&rn=%d&fmt=json&src=mbox&level=3&sourceset=tag_radio&extend=gxh&kid=%s&uid=%s",
			rn, util.GetString(params, "devid", "43513807"), uid)

	case "songs":
		fid := util.GetString(params, "fid", "")
		if fid == "" {
			return map[string]interface{}{"code": 400, "msg": "缺少参数 fid(电台ID, 可为负数如 -26711)"}, nil
		}
		num := util.GetInt(params, "num", 30)
		// play_radio.js: type=4 返回 GBK TSV 歌单; type=3 仅返回电台信息
		u = fmt.Sprintf("http://gxh2.kuwo.cn/newradio.nr?type=4&num=%d&uid=%s&login=1&ver=%s&fid=%s",
			num, uid, ver, fid)

	default:
		return map[string]interface{}{"code": 400, "msg": "action 仅支持 tree/songs"}, nil
	}

	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)


	out := map[string]interface{}{"code": 200, "action": action}
	if action == "songs" {
		songs := parseRadioTSV(body)
		if len(songs) > 0 {
			out["data"] = songs
			return out, nil
		}
	} else if json.Valid(body) {
		var tree interface{}
		if err := json.Unmarshal(body, &tree); err == nil {
			out["data"] = tree
			return out, nil
		}
	}
	out["raw"] = gbkDecode(body)
	return out, nil
}

// parseRadioTSV 解析 newradio.nr type=4 的 GBK TSV 歌单
// 格式: 首行为 fid\tcnt[\tcnt]，其后每行 rid\tartist\ttitle\tsig1,sig2\tflag
func parseRadioTSV(body []byte) []map[string]interface{} {
	text := gbkDecode(body)
	lines := strings.Split(text, "\n")
	var out []map[string]interface{}
	for i, line := range lines {
		line = strings.TrimRight(line, "\r")
		if i == 0 || line == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 {
			continue
		}
		m := map[string]interface{}{
			"rid":    f[0],
			"artist": f[1],
			"name":   f[2],
		}
		if sigs := strings.Split(f[3], ","); len(sigs) == 2 {
			m["nsig1"] = strings.TrimSpace(sigs[0])
			m["nsig2"] = strings.TrimSpace(sigs[1])
		}
		out = append(out, m)
	}
	return out
}

// gbkDecode GBK 转 UTF-8，失败时原样返回
func gbkDecode(b []byte) string {
	dec := simplifiedchinese.GBK.NewDecoder()
	out, err := dec.Bytes(b)
	if err != nil {
		return string(b)
	}
	return string(out)
}
