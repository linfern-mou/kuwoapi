/**
 * @fileoverview 酷我音乐踢人接口（强制下线其他设备）
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * URL 模板：/u.s?type=kick&uname=%s&pwd=%s&sid=%u&dev_id=%u&req_enc=gbk&res_enc=gbk
 *
 * 路由: /login/kick
 *
 * @module login_kick
 * @see REVERSE_SPEC.md 第三章第3.4节
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    type: 'kick',
    uname: params?.uname || params?.username || '',
    pwd: params?.pwd || params?.password || '',
    sid: params?.sid || params?.cookie?.sid || '',
    dev_id: params?.dev_id || '',
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
