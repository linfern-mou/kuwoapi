#!/usr/bin/env node
/**
 * 实证验证 deliver.kuwo.cn (GET/POST 多种变体)
 * 通过代理, 验证不同路径和方法
 */
const http = require('node:http');
const net = require('node:net');

const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 18080;

// 方法1: 通过 HTTP 代理 (绝对 URI)
function viaHttpProxy(method, targetHost, targetPath, body, extraHeaders) {
  return new Promise((resolve, reject) => {
    const bodyBuf = body ? Buffer.from(body, 'utf-8') : null;
    const headers = {
      'Host': targetHost,
      'User-Agent': 'Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)',
      'Cache-Control': 'no-cache',
      'Accept-Encoding': 'zlib',
      'Connection': 'close',
      ...extraHeaders,
    };
    if (bodyBuf) headers['Content-Length'] = bodyBuf.length;

    const req = http.request({
      host: PROXY_HOST, port: PROXY_PORT, method,
      path: `http://${targetHost}${targetPath}`,
      headers, timeout: 15000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks) }));
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('timeout')));
    if (bodyBuf) req.write(bodyBuf);
    req.end();
  });
}

// 方法2: 通过 CONNECT 隧道 (原始 HTTP)
function viaConnect(method, targetHost, targetPath, body, extraHeaders) {
  return new Promise((resolve, reject) => {
    const sock = net.connect(PROXY_PORT, PROXY_HOST, () => {
      sock.write(`CONNECT ${targetHost}:80 HTTP/1.1\r\nHost: ${targetHost}:80\r\n\r\n`);
    });
    let state = 'connect';
    let respBuf = Buffer.alloc(0);
    sock.on('data', (d) => {
      respBuf = Buffer.concat([respBuf, d]);
      if (state === 'connect') {
        const idx = respBuf.indexOf('\r\n\r\n');
        if (idx >= 0) {
          const connectResp = respBuf.slice(0, idx).toString('latin1');
          if (connectResp.includes('200')) {
            state = 'tunnel';
            // 发送实际请求
            const bodyBuf = body ? Buffer.from(body, 'utf-8') : null;
            let req = `${method} ${targetPath} HTTP/1.1\r\nHost: ${targetHost}\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)\r\nCache-Control: no-cache\r\nAccept-Encoding: zlib\r\nConnection: close\r\n`;
            for (const [k,v] of Object.entries(extraHeaders||{})) req += `${k}: ${v}\r\n`;
            if (bodyBuf) req += `Content-Length: ${bodyBuf.length}\r\n`;
            req += '\r\n';
            sock.write(req);
            if (bodyBuf) sock.write(bodyBuf);
            respBuf = respBuf.slice(idx + 4);
          } else {
            resolve({ status: -1, error: 'CONNECT failed: ' + connectResp, body: respBuf });
            sock.destroy();
          }
        }
      }
    });
    setTimeout(() => {
      resolve({ status: -2, error: 'timeout', body: respBuf });
      sock.destroy();
    }, 12000);
    sock.on('end', () => {
      if (state === 'tunnel') resolve({ status: 200, body: respBuf });
    });
    sock.on('error', (e) => resolve({ status: -3, error: e.message, body: respBuf }));
  });
}

(async () => {
  const sig1 = 2316766655, sig2 = 3918679961;
  const body = `<001><U_QRY>|<${sig1},${sig2}>|<0><><>|<0.0.0.0>|<rid>|<uip:0.0.0.0:0>|<new>|<nat:0>|<flags:262144><speer>|<ipdeny:no>|<loginid:>\r\n`;

  // 测试1: HTTP 代理 + POST /yl_res_manage.search
  console.log('=== [1] HTTP代理 POST /yl_res_manage.search ===');
  try {
    const r = await viaHttpProxy('POST', 'deliver.kuwo.cn', '/yl_res_manage.search', body, {});
    console.log(`status=${r.status} len=${r.body.length}`);
    console.log(r.body.toString('latin1').slice(0, 300));
  } catch(e) { console.error(e.message); }

  // 测试2: HTTP 代理 + GET /yl_res_manage.search?<body>
  console.log('\n=== [2] HTTP代理 GET /yl_res_manage.search?<body> ===');
  try {
    const qs = encodeURIComponent(body).replace(/%20/g,'+');
    const r = await viaHttpProxy('GET', 'deliver.kuwo.cn', `/yl_res_manage.search?${qs}`, null, {});
    console.log(`status=${r.status} len=${r.body.length}`);
    console.log(r.body.toString('latin1').slice(0, 300));
  } catch(e) { console.error(e.message); }

  // 测试3: CONNECT 隧道 + POST
  console.log('\n=== [3] CONNECT隧道 POST /yl_res_manage.search ===');
  try {
    const r = await viaConnect('POST', 'deliver.kuwo.cn', '/yl_res_manage.search', body, {});
    console.log(`status=${r.status} len=${r.body?.length||0} err=${r.error||''}`);
    if (r.body) console.log(r.body.toString('latin1').slice(0, 500));
  } catch(e) { console.error(e.message); }

  // 测试4: CONNECT 隧道 + GET (body as query)
  console.log('\n=== [4] CONNECT隧道 GET /yl_res_manage.search?<body> ===');
  try {
    const qs = encodeURIComponent(body).replace(/%20/g,'+');
    const r = await viaConnect('GET', 'deliver.kuwo.cn', `/yl_res_manage.search?${qs}`, null, {});
    console.log(`status=${r.status} len=${r.body?.length||0} err=${r.error||''}`);
    if (r.body) console.log(r.body.toString('latin1').slice(0, 500));
  } catch(e) { console.error(e.message); }

  // 测试5: 验证 deliver.kuwo.cn 根路径
  console.log('\n=== [5] HTTP代理 GET / (验证可达性) ===');
  try {
    const r = await viaHttpProxy('GET', 'deliver.kuwo.cn', '/', null, {});
    console.log(`status=${r.status} len=${r.body.length}`);
    console.log(r.body.toString('latin1').slice(0, 200));
  } catch(e) { console.error(e.message); }
})();
