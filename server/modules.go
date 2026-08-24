package server

import (
	"kuwoapi/module"
)

// loadModules 动态加载所有模块
// 对应 kugoumusic 的 main.js: fs.readdirSync('module').forEach(...)
func (s *Server) loadModules() {
	// 注册所有模块
	// 模块名即路由名：search → /search, song_url → /song/url
	s.modules["search"] = module.Search
	s.modules["download"] = module.Download
	s.modules["lyric"] = module.Lyric
	s.modules["song_url"] = module.SongURL
	s.modules["song_detail"] = module.SongDetail
	s.modules["rank"] = module.Rank
	s.modules["rank_list"] = module.RankList
	s.modules["playlist_rcm"] = module.PlaylistRcm
	s.modules["playlist_info"] = module.PlaylistInfo
	s.modules["rcm"] = module.Rcm
	s.modules["radio"] = module.Radio
}
