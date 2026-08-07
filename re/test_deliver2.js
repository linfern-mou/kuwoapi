#!/usr/bin/env node
/**
 * 实证验证 deliver.kuwo.cn (原始 socket, 真实 sig)
 * 格式来源: KwMV.dll 反汇编
 */
const net = require('node:net');

const RID = 'MUSIC_1108461';
const SIG1 = 521639994;  // ALFLAC
const SIG2 = 2344136090;
const KID = 15277654;
const UIP = '192.168.1.7';

// POST body 格式 (反汇编 VA=0x1005BD28):
// <%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>
const body = `<001><U_QRY>|<${SIG1},${SIG2}>|<${KID}><0><0>|<0>|<rid>|<uip:${UIP}>|<new>|<nat:0>|<flags:0><speer>|<ipdeny:no>0|<loginid:0>\r\n`;

function rawRequest(method, host, path, body, useGet) {
  return new Promise((resolve, reject) => {
    let req;
    if (method === 'POST') {
      const bodyBuf = Buffer.from(body, 'utf-8');
      req =
        `POST ${path} HTTP/1.1\r\n` +
        `Host: ${host}\r\n` +
        `User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)\r\n` +
        `Cache-Control: no-cache\r\n` +
        `Accept-Encoding: zlib\r\n` +
        `Content-Length: ${bodyBuf.length}\r\n` +
        `Connection: Keep-Alive\r\n` +
        `\r\n`;
      const sock = net.connect(80, host, () => { sock.write(req); sock.write(bodyBuf); });
      const chunks = [];
      sock.on('data', (c) => chunks.push(c));
      sock.on('end', () => resolve(Buffer.concat(chunks)));
      sock.on('error', reject);
      setTimeout(() => { sock.destroy(); resolve(Buffer.concat(chunks)); }, 8000);
    } else {
      // GET %s?%s HTTP/1.0  -- query 是 body 内容作为 query string
      req =
        `GET ${path}?${encodeURIComponent(body).replace(/%20/g,'+')} HTTP/1.0\r\n` +
        `Host: ${host}\r\n` +
        `User-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)\r\n` +
        `Cache-Control: no-cache\r\n` +
        `Accept-Encoding: zlib\r\n` +
        `Connection: Close\r\n` +
        `\r\n`;
      const sock = net.connect(80, host, () => { sock.write(req); });
      const chunks = [];
      sock.on('data', (c) => chunks.push(c));
      sock.on('end', () => resolve(Buffer.concat(chunks)));
      sock.on('error', reject);
      setTimeout(() => { sock.destroy(); resolve(Buffer.concat(chunks)); }, 8000);
    }
  });
}

(async () => {
  console.log('body:', JSON.stringify(body));
  console.log('\n=== POST /yl_res_manage.search ===');
  try {
    const resp = await rawRequest('POST', 'deliver.kuwo.cn', '/yl_res_manage.search', body);
    console.log('len:', resp.length);
    console.log(resp.slice(0, 1500).toString('latin1'));
  } catch (e) { console.error('POST err:', e.message); }

  console.log('\n=== GET /yl_res_manage.search?<body> ===');
  try {
    const resp = await rawRequest('GET', 'deliver.kuwo.cn', '/yl_res_manage.search', body);
    console.log('len:', resp.length);
    console.log(resp.slice(0, 1500).toString('latin1'));
  } catch (e) { console.error('GET err:', e.message); }

  // 也试不同路径变体
  console.log('\n=== POST /yl_res_manage.search (无 rid 字段试) ===');
  const body2 = `<001><U_QRY>|<${SIG1},${SIG2}>|<${KID}><0><0>|<0>|<rid>|<uip:${UIP}>|<new>|<nat:1>|<flags:131072><speer>|<ipdeny:no>0|<loginid:0>\r\n`;
  try {
    const resp = await rawRequest('POST', 'deliver.kuwo.cn', '/yl_res_manage.search', body2);
    console.log('len:', resp.length);
    console.log(resp.slice(0, 1500).toString('latin1'));
  } catch (e) { console.error('err:', e.message); }
})().catch(e => console.error(e));
