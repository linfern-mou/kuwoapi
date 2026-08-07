/**
 * @fileoverview 酷我音乐歌曲 ID3 信息查询接口
 *
 * 接口来源：default.zip 中 DLL strings 分析
 * 端点：http://datacenter.kuwo.cn/d.c?ft=music&cmkey=search_id3&ids=%s
 *
 * 路由: /song/id3
 *
 * @module song_id3
 */

module.exports = (params, useAxios) => {
  const ids = Array.isArray(params?.id) ? params.id.join(',') : params?.id || '';

  const dataMap = {
    ft: 'music',
    cmkey: 'search_id3',
    ids: ids,
  };

  return useAxios({
    baseURL: 'http://datacenter.kuwo.cn',
    url: '/d.c',
    method: 'GET',
    params: dataMap,
    cookie: params?.cookie || {},
    injectVer: false,
  });
};
