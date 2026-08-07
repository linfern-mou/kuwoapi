/**
 * @fileoverview 酷我音乐注册验证接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://reg.kuwo.cn/regsvr.auth?%d&%s
 *
 * 路由: /reg/auth
 *
 * @module reg_auth
 */

module.exports = (params, useAxios) => {
  const ts = Math.floor(Date.now() / 1000);
  const dataMap = {
    uid: params?.uid || '',
    sid: params?.sid || '',
  };

  return useAxios({
    baseURL: 'http://reg.kuwo.cn',
    url: `/regsvr.auth?${ts}&${params?.uid || ''}`,
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
