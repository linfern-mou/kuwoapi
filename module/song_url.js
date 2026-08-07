/**
 * @fileoverview 酷我音乐歌曲下载元数据接口
 *
 * 接口来源：default.zip 中 bin/Conf/default/config.ini 的 SecondSearch
 *   SecondSearch=http://search.kuwo.cn/r.s?stype=musicinfo&itemset=music_2014&alflac=1&pcmp4=1&ids=
 *
 * 响应格式：8字节头(zlib原始长度等) + zlib压缩的KV文本
 *   ids 需带 MUSIC_ 前缀（如 MUSIC_228908），纯数字返回空
 *
 * 返回内容：各音质的 sig1/sig2/filesize/bitrate 元数据
 *   供 P2P 客户端使用（压缩包确认下载走 KwP2PDLL P2P协议，非HTTP直链）
 *
 * 字段映射（来源：压缩包 KwMusicDLL.dll strings + KwModDownload.dll CNetResource）：
 *   S1 → sig1（CNetResource::Sign.sig1）
 *   S2 → sig2（CNetResource::Sign.sig2）
 *   SIZE → filesize（CNetResource::FileSize）
 *   BT → bitrate（CNetResource::Kpbs）
 *
 * 路由: /song/url
 *
 * @module song_url
 * @see REVERSE_SPEC.md 第三章
 */

const zlib = require('node:zlib');

module.exports = async (params, useAxios) => {
  const rid = String(params?.id || params?.rid || '').trim();
  if (!rid) {
    return {
      status: 200,
      body: { code: 400, msg: '缺少参数 id 或 rid' },
      cookie: [],
      headers: { 'content-type': 'application/json; charset=utf-8' },
    };
  }

  // ids 需要 MUSIC_ 前缀（来源：实测确认，纯数字返回空zlib）
  const ids = rid.startsWith('MUSIC_') ? rid : `MUSIC_${rid}`;

  const response = await useAxios({
    baseURL: 'http://search.kuwo.cn',
    url: '/r.s',
    method: 'GET',
    params: {
      stype: 'musicinfo',
      itemset: 'music_2014',
      alflac: 1,
      pcmp4: 1,
      ids: ids,
    },
    cookie: params?.cookie || {},
    injectVer: false,
    responseType: 'arraybuffer',
  });

  const buf = Buffer.from(response.body || []);

  // 响应不足（空zlib），说明 rid 无效或服务器无数据
  if (buf.length < 10) {
    return {
      status: 200,
      body: { code: 404, msg: `未找到 rid=${rid} 的歌曲信息`, rid },
      cookie: response.cookie,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    };
  }

  // 跳过前8字节头，zlib解压（wbits=15）
  let text;
  try {
    text = zlib.inflateSync(buf.slice(8)).toString('utf-8');
  } catch (e) {
    return {
      status: 200,
      body: {
        code: 500,
        msg: '解压失败',
        error: e.message,
        raw_hex: buf.slice(0, 20).toString('hex'),
      },
      cookie: response.cookie,
      headers: { 'content-type': 'application/json; charset=utf-8' },
    };
  }

  // 解析 KV 文本
  const lines = text.split(/\r?\n/);
  const info = { rid };
  const qualities = [];

  for (const line of lines) {
    const idx = line.indexOf('=');
    if (idx < 0) continue;
    const key = line.slice(0, idx).trim();
    const val = line.slice(idx + 1).trim();
    if (!key) continue;

    if (key === 'MUSICRID') {
      info.musicrid = val;
    } else if (key === 'FORMATS') {
      info.formats = val ? val.split('|').filter(Boolean) : [];
    } else if (key === 'TAG') {
      info.tag = val;
    } else if (key === 'MVPROVIDER') {
      info.mvprovider = val;
    } else {
      // 音质字段格式: KEY=S1:xxx|S2:xxx|SIZE:xxx|BT:xxx
      const parts = val.split('|');
      const q = { code: key };
      for (const p of parts) {
        const ci = p.indexOf(':');
        if (ci < 0) continue;
        const k = p.slice(0, ci).trim();
        const v = p.slice(ci + 1).trim();
        if (k === 'S1') q.sig1 = v;
        else if (k === 'S2') q.sig2 = v;
        else if (k === 'SIZE') q.filesize = parseInt(v, 10) || 0;
        else if (k === 'BT') q.bitrate = parseInt(v, 10) || 0;
      }
      if (q.sig1 || q.sig2 || q.filesize) {
        qualities.push(q);
      }
    }
  }

  info.qualities = qualities;

  return {
    status: 200,
    body: { code: 200, data: info },
    cookie: response.cookie,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  };
};
