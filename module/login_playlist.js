/**
 * @fileoverview 酷我音乐歌单登录接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * URL 模板：op=login&uname=%s&pwd=%s
 * 端点：http://pls.kuwo.cn/pl.svc
 *
 * 路由: /login/playlist
 *
 * @module login_playlist
 * @see REVERSE_SPEC.md 第三章第3.4节
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    op: 'login',
    uname: params?.uname || params?.username || '',
    pwd: params?.pwd || params?.password || '',
  };

  return useAxios({
    baseURL: 'http://pls.kuwo.cn',
    url: '/pl.svc',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
