/**
 * @fileoverview 酷我音乐歌曲播放地址接口
 *
 * 根据歌曲 ID 和音质获取播放链接。
 *
 * 路由: /song/url
 *
 * @example
 * // GET /song/url?id=123456&br=320
 * const res = await api.song_url({ id: '123456', br: 320 });
 *
 * @module song_url
 */

const qualityMap = {
  128: '128kmp3',
  192: '192kmp3',
  320: '320kmp3',
  2000: '2000kflac',
  1411: '1411kflac',
};

module.exports = (params, useAxios) => {
  const ids = Array.isArray(params?.id) ? params.id : [params?.id].filter(Boolean);
  const br = params?.br || 320;
  const format = qualityMap[br] || '320kmp3';

  const dataMap = {
    ids: ids.join(','),
    format,
    br: String(br),
    type: 'convert_url',
    platform: 'android',
    clientver: params?.clientver || '8.7.4.0',
  };

  return useAxios({
    url: '/url',
    method: 'GET',
    params: dataMap,
    encryptType: 'android',
    headers: { 'x-router': 'nmobi.kuwo.cn' },
    cookie: params?.cookie || {},
  });
};
