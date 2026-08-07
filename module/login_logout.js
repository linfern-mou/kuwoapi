/**
 * @fileoverview 酷我音乐登出接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * URL 模板：/u.s?type=logout&uid=%u&sid=%u&req_enc=gbk&res_enc=gbk
 *
 * 路由: /login/logout
 *
 * @module login_logout
 * @see REVERSE_SPEC.md 第三章第3.4节
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    type: 'logout',
    uid: params?.uid || params?.cookie?.uid || '',
    sid: params?.sid || params?.cookie?.sid || '',
    req_enc: 'gbk',
    res_enc: 'gbk',
  };

  return useAxios({
    baseURL: 'http://pc.i.kuwo.cn',
    url: '/u.s',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
