#!/usr/bin/env node
/* 测试 SearchServer/resserver 的直接 TCP 协议
 * 1. search.kuwo.cn 获取当前 ALFLAC S1/S2
 * 2. CONNECT 到 SearchServer:80, 发送裸 body (直接TCP), 看响应
 * 3. 也测试 resserver
 */
const net = require('net');
const zlib = require('zlib');

const PROXY_HOST = '127.0.0.1';
const PROXY_PORT = 18080;

function viaProxy(targetHost, targetPort, reqBuf, timeout=15000) {
  return new Promise((resolve) => {
    const sock = net.connect(PROXY_PORT, PROXY_HOST, () => {
      sock.write(`CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\nHost: ${targetHost}:${targetPort}\r\n\r\n`);
    });
    let state = 0, cbuf = [], rchunks = [];
    sock.on('data', (d) => {
      if (state === 0) {
        cbuf.push(d);
        const t = Buffer.concat(cbuf).toString('latin1');
        if (t.includes('\r\n\r\n')) {
          if (/^HTTP\/1\.[01] 200/.test(t)) { state = 1; sock.write(reqBuf); }
          else { sock.destroy(); resolve({err: 'CONNECT failed: ' + t.split('\r\n')[0]}); }
        }
      } else rchunks.push(d);
    });
    sock.on('end', () => state===1 ? resolve(Buffer.concat(rchunks)) : resolve({err:'end-before-tunnel'}));
    sock.on('error', e => resolve({err: e.message}));
    sock.setTimeout(timeout, () => { sock.destroy(); resolve({err:'timeout', got: rchunks.length?Buffer.concat(rchunks):null}); });
  });
}

const UA = 'Mozilla/4.0 (compatible; MSIE 7.0; MSIE 6.0; Windows NT 5.0; .NET CLR 1.1.4322)';

async function getMeta(rid) {
  const req = `GET /r.s?stype=musicinfo&itemset=music_2014&alflac=1&pcmp4=1&ids=${rid} HTTP/1.0\r\nHost: search.kuwo.cn\r\nUser-Agent: ${UA}\r\nConnection: close\r\n\r\n`;
  const r = await viaProxy('search.kuwo.cn', 80, Buffer.from(req));
  if (r.err) return r;
  const text = r.toString('latin1');
  const hi = text.indexOf('\r\n\r\n');
  const body = r.slice(hi+4);
  const z = body.indexOf(Buffer.from([0x78,0x9c]));
  if (z < 0) return {err:'no-zlib'};
  const inf = zlib.inflateSync(body.slice(z));
  return inf.toString('utf8');
}

function buildBody(sig1, sig2) {
  return `<001><U_QRY>|<${sig1},${sig2}>|<0><><>|<>|<rid>|<uip:0.0.0.0:0>|<new>|<nat:0>|<flags:0><speer>|<ipdeny:no>|<loginid:>\r\n`;
}

function dump(label, buf) {
  if (!buf) { console.log(`  ${label}: (null)`); return; }
  console.log(`  ${label}: len=${buf.length}`);
  console.log(`    hex: ${buf.slice(0,80).toString('hex')}`);
  const l = buf.slice(0,200).toString('latin1');
  console.log(`    latin1: ${JSON.stringify(l)}`);
  // 尝试 zlib
  const z = buf.indexOf(Buffer.from([0x78,0x9c]));
  if (z >= 0) {
    try { const inf = zlib.inflateSync(buf.slice(z)); console.log(`    zlib@${z}: ${inf.slice(0,200).toString('latin1')}`); } catch(e){}
  }
}

(async () => {
  console.log('=== [1] 获取 ALFLAC S1/S2 ===');
  const meta = await getMeta('MUSIC_1108461');
  if (meta.err) { console.log('  ERR:', meta.err); return; }
  const m = meta.match(/ALFLAC=S1:(\d+)\|S2:(\d+)\|SIZE:(\d+)/);
  if (!m) { console.log('  no ALFLAC'); console.log(meta.slice(0,400)); return; }
  const sig1 = m[1], sig2 = m[2], size = m[3];
  console.log(`  ALFLAC sig1=${sig1} sig2=${sig2} size=${size}`);

  const body = buildBody(sig1, sig2);
  console.log('  body:', JSON.stringify(body));

  const targets = [
    {host:'60.9.52.164', name:'SearchServer1'},
    {host:'211.99.9.14', name:'SearchServer2'},
    {host:'60.10.78.77', name:'SearchServer3'},
    {host:'39.156.123.34', name:'resserver'},
  ];

  for (const t of targets) {
    console.log(`\n=== [2] ${t.host} (${t.name}) 裸 TCP body ===`);
    const r = await viaProxy(t.host, 80, Buffer.from(body));
    if (r.err) { console.log('  ERR:', r.err); if(r.got) dump('partial', r.got); }
    else dump('resp', r);

    // 也测试: 只发 body 不带 \r\n
    console.log(`--- ${t.host} 裸 body (无\\r\\n) ---`);
    const bodyNoNL = body.replace(/\r\n$/, '');
    const r2 = await viaProxy(t.host, 80, Buffer.from(bodyNoNL));
    if (r2.err) { console.log('  ERR:', r2.err); }
    else dump('resp', r2);

    // 测试: HTTP POST 但看原始(可能非HTTP)
    console.log(`--- ${t.host} HTTP POST (看原始) ---`);
    const req = `POST /yl_res_manage.search HTTP/1.1\r\nHost: ${t.host}\r\nUser-Agent: ${UA}\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`;
    const r3 = await viaProxy(t.host, 80, Buffer.from(req));
    if (r3.err) { console.log('  ERR:', r3.err); }
    else dump('resp', r3);
  }
})();
