#!/usr/bin/env node
/**
 * 测试 deliver.kuwo.cn 多种协议/路径组合
 * - HTTPS (443) via CONNECT
 * - HTTP (80) via CONNECT (无代理标头)
 * - 不同路径变体
 */
const net = require('node:net');
const tls = require('node:tls');

const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 18080;

function viaHttpConnectTunnel(targetHost, targetPort, rawRequest) {
  return new Promise((resolve) => {
    const sock = net.connect(PROXY_PORT, PROXY_HOST, () => {
      sock.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n\r\n`);
    });
    let state = 'connect';
    let buf = Buffer.alloc(0);
    const t = setTimeout(() => {
      resolve({ status: -2, err: 'timeout', body: buf });
      sock.destroy();
    }, 15000);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (state === 'connect') {
        const idx = buf.indexOf('\r\n\r\n');
        if (idx >= 0) {
          const conn = buf.slice(0, idx).toString('latin1');
          if (conn.match(/200/)) {
            state = 'tunnel';
            sock.write(rawRequest);
            buf = buf.slice(idx + 4);
          } else {
            clearTimeout(t);
            resolve({ status: -1, err: 'CONNECT failed: ' + conn, body: buf });
            sock.destroy();
          }
        }
      }
    });
    sock.on('end', () => {
      if (state === 'tunnel') {
        clearTimeout(t);
        resolve({ status: 0, body: buf });
      }
    });
    sock.on('error', (e) => {
      clearTimeout(t);
      resolve({ status: -3, err: e.message, body: buf });
    });
  });
}

function viaHttpsConnect(targetHost, rawRequest) {
  return new Promise((resolve) => {
    const sock = net.connect(PROXY_PORT, PROXY_HOST, () => {
      sock.write(`CONNECT ${targetHost}:443 HTTP/1.1\r\nHost: ${targetHost}:443\r\n\r\n`);
    });
    let state = 'connect';
    let buf = Buffer.alloc(0);
    const t = setTimeout(() => {
      resolve({ status: -2, err: 'timeout', body: buf });
      sock.destroy();
    }, 15000);
    sock.on('data', (d) => {
      buf = Buffer.concat([buf, d]);
      if (state === 'connect') {
        const idx = buf.indexOf('\r\n\r\n');
        if (idx >= 0) {
          const conn = buf.slice(0, idx).toString('latin1');
          if (conn.match(/200/)) {
            state = 'tunnel';
            // 升级到 TLS
            sock.removeAllListeners('data');
            const tlsSock = tls.connect({
              socket: sock,
              servername: targetHost,
              rejectUnauthorized: false,
            }, () => {
              tlsSock.write(rawRequest);
            });
            let tlsBuf = Buffer.alloc(0);
            tlsSock.on('data', (d) => { tlsBuf = Buffer.concat([tlsBuf, d]); });
            tlsSock.on('end', () => {
              clearTimeout(t);
              resolve({ status: 0, body: tlsBuf });
            });
            tlsSock.on('error', (e) => {
              clearTimeout(t);
              resolve({ status: -4, err: 'TLS: ' + e.message, body: tlsBuf });
            });
          } else {
            clearTimeout(t);
            resolve({ status: -1, err: 'CONNECT failed: ' + conn, body: buf });
            sock.destroy();
          }
        }
      }
    });
    sock.on('error', (e) => {
      clearTimeout(t);
      resolve({ status: -3, err: e.message, body: buf });
    });
  });
}

const sig1 = 2316766655, sig2 = 3918679961;
const body = `<001><U_QRY>|<${sig1},${sig2}>|<0><><>|<0.0.0.0>|<rid>|<uip:0.0.0.0:0>|<new>|<nat:0>|<flags:262144><speer>|<ipdeny:no>|<loginid:>\r\n`;
const bodyLen = Buffer.byteLength(body);

const paths = [
  '/yl_res_manage.search',
  '/yl_res_manage.spread',
  '/yl_res_manage',
  '/yl_res_manage.search?',
];

(async () => {
  // 1) HTTPS POST 各路径
  for (const path of paths) {
    const req = `POST ${path} HTTP/1.1\r\nHost: deliver.kuwo.cn\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)\r\nCache-Control: no-cache\r\nAccept-Encoding: zlib\r\nContent-Length: ${bodyLen}\r\nConnection: close\r\n\r\n${body}`;
    console.log(`\n=== HTTPS POST ${path} ===`);
    const r = await viaHttpsConnect('deliver.kuwo.cn', req);
    console.log(`  status=${r.status} err=${r.err||''} len=${r.body?.length||0}`);
    if (r.body && r.body.length) {
      console.log('  --- response (first 500 bytes) ---');
      console.log(r.body.toString('latin1').slice(0, 500));
    }
  }

  // 2) HTTP GET 原始 body 作 query string (不 URL 编码)
  console.log('\n=== HTTP GET /yl_res_manage.search?<raw body> ===');
  const reqGet = `GET /yl_res_manage.search?${body.replace(/\r\n/g,'')} HTTP/1.0\r\nHost: deliver.kuwo.cn\r\nUser-Agent: Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)\r\nCache-Control: no-cache\r\nAccept-Encoding: zlib\r\nConnection: close\r\n\r\n`;
  const r2 = await viaHttpConnectTunnel('deliver.kuwo.cn', 80, reqGet);
  console.log(`  status=${r2.status} err=${r2.err||''} len=${r2.body?.length||0}`);
  if (r2.body && r2.body.length) {
    console.log('  --- response ---');
    console.log(r2.body.toString('latin1').slice(0, 500));
  }

  // 3) HTTP 根路径
  console.log('\n=== HTTP GET / ===');
  const reqRoot = `GET / HTTP/1.0\r\nHost: deliver.kuwo.cn\r\nConnection: close\r\n\r\n`;
  const r3 = await viaHttpConnectTunnel('deliver.kuwo.cn', 80, reqRoot);
  console.log(`  status=${r3.status} err=${r3.err||''} len=${r3.body?.length||0}`);
  if (r3.body && r3.body.length) {
    console.log('  --- response ---');
    console.log(r3.body.toString('latin1').slice(0, 500));
  }
})();
