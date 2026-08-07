/**
 * @fileoverview 酷我音乐 P2P 资源签名刷新接口
 *
 * 接口来源：default.zip 中 pd.dll 的 GetResourceSig 函数 strings 分析
 *   - config.ini: SigServer=http://rid.kuwo.cn/sig.s?w=
 *   - pd.dll: getressig url=%s, GET %s HTTP/1.0, sig1=%u, sig2=%u
 *   - pd.dll: &c=mbox
 *
 * 请求格式（来源：pd.dll strings）:
 *   GET http://rid.kuwo.cn/sig.s?w={rid}&c=mbox HTTP/1.0
 *   Host: rid.kuwo.cn
 *   User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)
 *   Pragma: no-cache
 *   Cache-Control: no-cache
 *   Connection: close
 *
 * 响应格式: 文本，包含 sig1=%u 和 sig2=%u
 *
 * 用途: P2P 下载前刷新资源签名（sig1/sig2 可能过期）
 *
 * 路由: /song/sig
 *
 * @module song_sig
 * @see REVERSE_SPEC.md 3.11.1
 */

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

  // ids 需要 MUSIC_ 前缀的 rid 数字部分
  const ridNum = rid.replace(/^MUSIC_/, '');

  const response = await useAxios({
    baseURL: 'http://rid.kuwo.cn',
    url: '/sig.s',
    method: 'GET',
    params: {
      w: ridNum,
      c: 'mbox',
    },
    cookie: params?.cookie || {},
    injectVer: false,
    headers: {
      'User-Agent':
        'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)',
      Pragma: 'no-cache',
      'Cache-Control': 'no-cache',
      Connection: 'close',
    },
  });

  // 解析响应文本中的 sig1= 和 sig2=
  const text = typeof response.body === 'string' ? response.body : String(response.body || '');
  const sig1Match = text.match(/sig1=(\d+)/i);
  const sig2Match = text.match(/sig2=(\d+)/i);

  const data = {
    rid: ridNum,
    sig1: sig1Match ? sig1Match[1] : null,
    sig2: sig2Match ? sig2Match[1] : null,
    raw: text.substring(0, 500),
  };

  return {
    status: response.status,
    body: { code: 200, data },
    cookie: response.cookie,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  };
};
