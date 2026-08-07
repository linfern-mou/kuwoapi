/**
 * @fileoverview 酷我音乐注册页面接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://pc.i.kuwo.cn/US/mbox/login2015new/reg.jsp?
 *
 * 路由: /login/reg
 *
 * @module login_reg
 * @see REVERSE_SPEC.md 第三章第3.4节
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    from: 'pc',
  };

  return useAxios({
    baseURL: 'http://pc.i.kuwo.cn',
    url: '/US/mbox/login2015new/reg.jsp',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
