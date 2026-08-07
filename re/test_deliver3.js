#!/usr/bin/env node
/**
 * 实证验证 deliver.kuwo.cn/yl_res_manage.search (通过代理)
 * 格式来源: KwMV.dll 反汇编 VA=0x1005BD28, 0x1005B8B0
 *
 * 完整流程:
 * 1. rid.kuwo.cn/sig.s 刷新签名 (获取最新 sig1/sig2)
 * 2. deliver.kuwo.cn/yl_res_manage.search 检索资源服务器
 *
 * body 格式 (13个参数, 反汇编确认):
 * <%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>
 *  001  U_QRY  sig1 sig2  uip  s1  s2   uipstr           lip:port      port      flags        cdnreq      netid
 */
const http = require('node:http');

const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 18080;

// 从 act.log 提取的真实数据
const RID = 'MUSIC_1108461';  // Letting Go - 蔡健雅
const RID_NUM = '1108461';

// 通过代理发送 HTTP 请求
function sendViaProxy(method, targetHost, targetPath, body, headers) {
  return new Promise((resolve, reject) => {
    const bodyBuf = body ? Buffer.from(body, 'utf-8') : null;
    const reqHeaders = {
      'Host': targetHost,
      'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)',
      'Cache-Control': 'no-cache',
      ...headers,
    };
    if (bodyBuf) reqHeaders['Content-Length'] = bodyBuf.length;

    const proxyReq = http.request({
      host: PROXY_HOST,
      port: PROXY_PORT,
      method,
      path: `http://${targetHost}${targetPath}`,
      headers: reqHeaders,
      timeout: 15000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({
        status: res.statusCode,
        headers: res.headers,
        body: Buffer.concat(chunks),
      }));
    });
    proxyReq.on('error', reject);
    proxyReq.on('timeout', () => { proxyReq.destroy(new Error('timeout')); });
    if (bodyBuf) proxyReq.write(bodyBuf);
    proxyReq.end();
  });
}

// 1. 刷新签名: rid.kuwo.cn/sig.s?w={rid}&c=mbox
async function refreshSig(ridNum) {
  console.log(`\n[1] 刷新签名: rid.kuwo.cn/sig.s?w=${ridNum}&c=mbox`);
  const resp = await sendViaProxy('GET', 'rid.kuwo.cn', `/sig.s?w=${ridNum}&c=mbox`, null, {
    'Accept': '*/*',
    'Connection': 'close',
  });
  console.log(`  status=${resp.status} len=${resp.body.length}`);
  const text = resp.body.toString('latin1');
  console.log(`  body: ${text.slice(0, 300)}`);
  // 解析 sig1=xxx sig2=xxx
  const m1 = text.match(/sig1=(\d+)/i);
  const m2 = text.match(/sig2=(\d+)/i);
  if (m1 && m2) {
    return { sig1: parseInt(m1[1]), sig2: parseInt(m2[1]) };
  }
  return null;
}

// 2. deliver 请求
async function searchResource(sig1, sig2) {
  // body 格式 (反汇编 VA=0x1005BD28):
  // <%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>
  // arg5 = 用户IP dword (act.log sip:0.0.0.0 -> 0)
  // arg6,7 = 全局配置字符串 (默认空)
  // arg8 = 用户IP字符串 "0.0.0.0"
  // arg9 = 本地IP:Port "0.0.0.0:0"
  // arg10 = port (0)
  // arg11 = flags (0x40000 默认)
  // arg12 = cdnreq ("|<cdnreq>" 或空)
  // arg13 = loginid (NetID, 默认空)
  const userIpDword = 0;
  const str1 = '';
  const str2 = '';
  const userIpStr = '0.0.0.0';
  const localIpPort = '0.0.0.0:0';
  const port = 0;
  const flags = 0x40000;
  const cdnreq = '';
  const loginid = '';

  const body = `<001><U_QRY>|<${sig1},${sig2}>|<${userIpDword}><${str1}><${str2}>|<${userIpStr}>|<rid>|<uip:${localIpPort}>|<new>|<nat:${port}>|<flags:${flags}><speer>|<ipdeny:no>${cdnreq}|<loginid:${loginid}>\r\n`;

  console.log(`\n[2] deliver 请求: POST /yl_res_manage.search`);
  console.log(`  body: ${JSON.stringify(body)}`);

  // POST 模板 (VA=0x1005B8B0):
  // POST %s HTTP/1.1\r\nHost: deliver.kuwo.cn\r\n...Content-Length: %d\r\nConnection: Keep-Alive\r\n\r\n%s
  const resp = await sendViaProxy('POST', 'deliver.kuwo.cn', '/yl_res_manage.search', body, {
    'Accept-Encoding': 'zlib',
    'Connection': 'Keep-Alive',
  });
  console.log(`  status=${resp.status} len=${resp.body.length}`);
  console.log(`  headers:`, resp.headers);
  // 显示前 2000 字节
  const text = resp.body.toString('latin1');
  console.log(`  body(前2000):\n${text.slice(0, 2000)}`);
  return resp;
}

(async () => {
  try {
    // 步骤1: 刷新签名
    const sig = await refreshSig(RID_NUM);
    if (!sig) {
      console.log('签名刷新失败, 尝试用 act.log 中的旧签名');
      // act.log 中 P2P_DOWN_FILE 的 sig1/sig2 (已可能过期)
      const oldSig1 = 2316766655;
      const oldSig2 = 3918679961;
      console.log(`  使用旧签名: sig1=${oldSig1} sig2=${oldSig2}`);
      await searchResource(oldSig1, oldSig2);
      return;
    }
    console.log(`  获取签名: sig1=${sig.sig1} sig2=${sig.sig2}`);

    // 步骤2: deliver 检索
    await searchResource(sig.sig1, sig.sig2);
  } catch (e) {
    console.error('错误:', e.message);
  }
})();
