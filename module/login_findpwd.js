/**
 * @fileoverview 酷我音乐找回密码接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：
 * - http://pc.i.kuwo.cn/US/mbox/login2015new/findPwd.jsp （新版）
 * - http://pc.i.kuwo.cn/US/mbox/login2015/findPwd.jsp （旧版）
 *
 * 路由: /login/findpwd
 *
 * @module login_findpwd
 * @see REVERSE_SPEC.md 第三章第3.4节
 */

module.exports = (params, useAxios) => {
  const useNew = params?.new !== false;
  const path = useNew ? '/US/mbox/login2015new/findPwd.jsp' : '/US/mbox/login2015/findPwd.jsp';

  const dataMap = {
    from: 'pc',
  };

  return useAxios({
    baseURL: 'http://pc.i.kuwo.cn',
    url: path,
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
