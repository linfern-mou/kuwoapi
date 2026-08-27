package p2p

import (
	"fmt"
	"net/http"
	"strings"
)

// DownloadInfo 下载信息
type DownloadInfo struct {
	RID     string `json:"rid"`
	Name    string `json:"name"`
	Artist  string `json:"artist"`
	URL     string `json:"url"`
	Format  string `json:"format"`
	Token   string `json:"token"`
	Quality string `json:"quality"`
}

// BestQualityAudio 获取最佳音质
func BestQualityAudio(song MusicPaySong) *AudioItem {
	if len(song.Audio) == 0 {
		return nil
	}
	// 音质优先级: FLAC > OGGH > MP3H > AAC
	priority := map[string]int{
		"ALFLAC": 100, "OGGH": 90, "MP3H": 80, "AAC96": 70,
		"MP3128": 60, "OGG96": 50, "WMA128": 40, "AAC48": 30,
	}
	var best *AudioItem
	bestScore := -1
	for i := range song.Audio {
		score := priority[song.Audio[i].RowFmt]
		if score > bestScore && song.Audio[i].Avaliable == 1 {
			bestScore = score
			best = &song.Audio[i]
		}
	}
	return best
}

// ParseDownloadURL 从AudioItem解析下载URL
func ParseDownloadURL(audio AudioItem) string {
	sourceID := audio.P2pAudiosourceid
	fmtStr := audio.Fmt
	
	// 格式: 254547612 + 30106 + trackmedia + F000002cjEhn44AZ3y + ext
	const prefixLen = 9 // "254547612"
	
	if !strings.Contains(sourceID, "trackmedia") {
		return ""
	}
	
	idx := strings.Index(sourceID, "trackmedia")
	if idx < prefixLen {
		return ""
	}
	
	resID := sourceID[prefixLen:idx]
	filename := sourceID[idx+len("trackmedia"):]
	
	ext := getExtFromFmt(fmtStr)
	cdn := "kw-lw.kuwo.cn"
	
	return fmt.Sprintf("http://%s/resource/%s/trackmedia/%s.%s?source=pc_player.%s",
		cdn, resID, filename, ext, ext)
}

// getExtFromFmt 根据格式字符串获取扩展名
func getExtFromFmt(fmtStr string) string {
	switch {
	case strings.Contains(strings.ToUpper(fmtStr), "FLAC"):
		return "flac"
	case strings.Contains(strings.ToUpper(fmtStr), "MP3"):
		return "mp3"
	case strings.Contains(strings.ToUpper(fmtStr), "OGG"):
		return "ogg"
	case strings.Contains(strings.ToUpper(fmtStr), "WMA"):
		return "wma"
	case strings.Contains(strings.ToUpper(fmtStr), "AAC"):
		return "m4a"
	default:
		return "mp3"
	}
}

// GetDownloadInfo 获取完整下载信息（无需登录）
func GetDownloadInfo(client *http.Client, rid uint64) (*DownloadInfo, error) {
	payResp, err := DoMusicPay(client, rid)
	if err != nil {
		return nil, err
	}
	
	if len(payResp.Songs) == 0 {
		return nil, fmt.Errorf("no song found for rid=%d", rid)
	}
	
	song := payResp.Songs[0]
	audio := BestQualityAudio(song)
	if audio == nil {
		return nil, fmt.Errorf("no available audio for rid=%d", rid)
	}
	
	downloadURL := ParseDownloadURL(*audio)
	token := song.Token[audio.Quality]
	
	return &DownloadInfo{
		RID:     song.ID,
		Name:    song.Name,
		Artist:  song.Artist,
		URL:     downloadURL,
		Format:  audio.Fmt,
		Token:   token,
		Quality: audio.Quality,
	}, nil
}
