/**
 * @fileoverview 酷我音乐歌单（喜欢列表）接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://nplserver.kuwo.cn/pl.svc?encode=utf-8&op=getlikeinfo&uid=%s
 *
 * 路由: /playlist/like
 *
 * @module playlist_like
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    encode: 'utf-8',
    op: 'getlikeinfo',
    uid: params?.uid || params?.cookie?.uid || '',
  };

  return useAxios({
    baseURL: 'http://nplserver.kuwo.cn',
    url: '/pl.svc',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
