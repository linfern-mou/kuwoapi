/**
 * @fileoverview 酷我音乐用户信息接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://pc.i.kuwo.cn/US_NEW/kuwo/vuser
 *
 * 路由: /user/info
 *
 * @module user_info
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    uid: params?.uid || params?.cookie?.uid || '',
    sid: params?.sid || params?.cookie?.sid || '',
  };

  return useAxios({
    baseURL: 'http://pc.i.kuwo.cn',
    url: '/US_NEW/kuwo/vuser',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
