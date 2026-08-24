package module

import (
	"strconv"
	"strings"
)

// parseParamChain 解析酷我歌曲签名字段（ksong.s 的 param / pl.svc 的 params）
// 来源：html/webdata/netsong/js/comm_search.js saveMusicInfo + listening.js bang 分支
// 格式（分号分隔）：
//
//	[0]name [1]artist [2]album [3]NSIG1 [4]NSIG2 [5]MUSICRID
//	[6]MP3NSIG1 [7]MP3NSIG2 [8]MP3RID [9..]保留 [11]MVRID [12]HASECHO
//
// NSIG1/NSIG2 即 P2P 协议中的 sig1/sig2（KwMV.dll U_QRY 的 sig:(%lu,%lu)，
// act.log DOWN_MUSIC 记录 S1/S2）
func parseParamChain(s string) map[string]interface{} {
	out := make(map[string]interface{}, 6)
	if s == "" {
		return out
	}
	p := strings.Split(s, ";")
	if len(p) > 3 {
		out["nsig1"] = parseUintOrRaw(p[3])
	}
	if len(p) > 4 {
		out["nsig2"] = parseUintOrRaw(p[4])
	}
	if len(p) > 5 {
		out["musicrid"] = p[5]
	}
	if len(p) > 7 {
		out["mp3nsig1"] = parseUintOrRaw(p[6])
		out["mp3nsig2"] = parseUintOrRaw(p[7])
	}
	if len(p) > 8 {
		out["mp3rid"] = p[8]
	}
	return out
}

func parseUintOrRaw(s string) interface{} {
	if n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 64); err == nil {
		return n
	}
	return s
}

// mergeParam 将签名字段并入目标 map
func mergeParam(dst map[string]interface{}, chain string) {
	for k, v := range parseParamChain(chain) {
		dst[k] = v
	}
}
