/**
 * @fileoverview 酷我音乐登录接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://pc.i.kuwo.cn/US_NEW/kuwo/login_kw
 *
 * 路由: /login
 *
 * @module login
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    uname: params?.uname || params?.username || '',
    pwd: params?.pwd || params?.password || '',
  };

  return useAxios({
    baseURL: 'http://pc.i.kuwo.cn',
    url: '/US_NEW/kuwo/login_kw',
    method: 'POST',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
