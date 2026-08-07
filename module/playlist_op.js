/**
 * @fileoverview 酷我音乐歌单操作接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://pls.kuwo.cn/pl.svc
 * 支持操作：op=add/del/update/validate/login/query/submit
 *
 * 参数格式（来源压缩包）：
 * - op=add&uid=%d&sid=%s&name=%s
 * - op=del&uid=%d&sid=%s&pid=%s
 * - op=update&uid=%d&sid=%s&name=%s&pid=%s&rids=
 * - op=validate&uid=%d&sid=%s&num=%d
 * - op=login&uname=%s&pwd=%s
 *
 * 路由: /playlist/op
 *
 * @module playlist_op
 */

module.exports = (params, useAxios) => {
  const dataMap = {
    op: params?.op || 'query',
    uid: params?.uid || params?.cookie?.uid || '',
    sid: params?.sid || params?.cookie?.sid || '',
  };

  // 根据操作类型补充参数
  switch (dataMap.op) {
    case 'add':
      dataMap.name = params?.name || '';
      break;
    case 'del':
      dataMap.pid = params?.pid || '';
      break;
    case 'update':
      dataMap.name = params?.name || '';
      dataMap.pid = params?.pid || '';
      dataMap.rids = params?.rids || '';
      break;
    case 'validate':
      dataMap.num = params?.num || 0;
      break;
    case 'login':
      dataMap.uname = params?.uname || '';
      dataMap.pwd = params?.pwd || '';
      delete dataMap.uid;
      delete dataMap.sid;
      break;
    case 'query':
      dataMap.signver = 'new';
      dataMap.action = params?.action || '';
      dataMap.ids = params?.ids || '';
      dataMap.accttype = 1;
      break;
    case 'submit':
      dataMap.action = params?.action || '';
      dataMap.pid = params?.pid || '';
      dataMap.id = params?.id || '';
      dataMap.br = params?.br || 320;
      dataMap.fmt = params?.fmt || 'mp3';
      dataMap.accttype = 1;
      dataMap.src = 'mbox';
      break;
  }

  return useAxios({
    baseURL: 'http://pls.kuwo.cn',
    url: '/pl.svc',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
