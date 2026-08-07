#!/usr/bin/env node
/* 测试 resserver 响应模式: 多首歌 + rid 替换 + base64 解码分析 */
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
    sock.setTimeout(timeout, () => { sock.destroy(); resolve({err:'timeout'}); });
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
  return zlib.inflateSync(body.slice(z)).toString('utf8');
}

// bodyfmt: <%s><%s>|<%u,%u>|<%u><%s><%s>|<%s>|<rid>|<uip:%s>|<new>|<nat:%u>|<flags:%u><speer>|<ipdeny:no>%s|<loginid:%s>\r\n
function buildBody(sig1, sig2, ridVal) {
  // ridVal: 用 rid 替换字面量 <rid>，或保持 <rid>
  const ridField = ridVal ? `<${ridVal}>` : `<rid>`;
  return `<001><U_QRY>|<${sig1},${sig2}>|<0><><>|<>|${ridField}|<uip:0.0.0.0:0>|<new>|<nat:0>|<flags:0><speer>|<ipdeny:no>|<loginid:>\r\n`;
}

async function postResserver(body) {
  const req = `POST /yl_res_manage.search HTTP/1.1\r\nHost: 39.156.123.34\r\nUser-Agent: ${UA}\r\nCache-Control: no-cache\r\nAccept-Encoding: zlib\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`;
  const r = await viaProxy('39.156.123.34', 80, Buffer.from(req));
  if (r.err) return {err: r.err};
  const text = r.toString('latin1');
  const hi = text.indexOf('\r\n\r\n');
  return {status: text.slice(0,hi).split('\r\n')[0], body: r.slice(hi+4).toString('latin1').trim()};
}

function decodeB64(s) {
  try { return Buffer.from(s, 'base64'); } catch(e) { return null; }
}

(async () => {
  const rids = ['MUSIC_1108461', 'MUSIC_52286056'];
  const metas = {};
  for (const rid of rids) {
    const m = await getMeta(rid);
    if (m.err) { console.log(rid, 'meta err:', m.err); continue; }
    const flac = m.match(/ALFLAC=S1:(\d+)\|S2:(\d+)\|SIZE:(\d+)/);
    const mp3h = m.match(/MP3H=S1:(\d+)\|S2:(\d+)\|SIZE:(\d+)/);
    metas[rid] = {flac: flac && {s1:flac[1], s2:flac[2], size:flac[3]}, mp3h: mp3h && {s1:mp3h[1], s2:mp3h[2], size:mp3h[3]}, raw: m};
    console.log(`${rid}: ALFLAC=${JSON.stringify(metas[rid].flac)} MP3H=${JSON.stringify(metas[rid].mp3h)}`);
  }

  console.log('\n=== resserver POST 测试 ===');
  const tests = [];
  for (const rid of rids) {
    if (!metas[rid]) continue;
    for (const fmt of ['flac', 'mp3h']) {
      const s = metas[rid][fmt];
      if (!s) continue;
      tests.push({label:`${rid} ${fmt} <rid>字面量`, sig1:s.s1, sig2:s.s2, ridVal:null});
      tests.push({label:`${rid} ${fmt} rid替换`, sig1:s.s1, sig2:s.s2, ridVal:rid});
      tests.push({label:`${rid} ${fmt} rid裸值`, sig1:s.s1, sig2:s.s2, ridVal:rid, bare:true});
    }
  }

  for (const t of tests) {
    let body = buildBody(t.sig1, t.sig2, t.ridVal);
    if (t.bare) body = body.replace(`<${t.ridVal}>`, t.ridVal);
    const r = await postResserver(body);
    const b64dec = r.body ? decodeB64(r.body) : null;
    console.log(`\n[${t.label}]`);
    console.log(`  body: ${JSON.stringify(body)}`);
    console.log(`  resp: ${r.status || r.err} body="${r.body}"`);
    if (b64dec) {
      console.log(`  b64dec hex: ${b64dec.toString('hex')} (len=${b64dec.length})`);
      // 尝试 zlib
      try { const inf = zlib.inflateSync(b64dec); console.log(`  b64+zlib: ${inf.toString('latin1')}`); } catch(e){}
      try { const inf = zlib.inflateRawSync(b64dec); console.log(`  b64+rawzlib: ${inf.toString('latin1')}`); } catch(e){}
      // 尝试 xor 常见 key
      for (const k of [0x5a, 0xaa, 0xff, 0x37, 0x69]) {
        const x = Buffer.from(b64dec.map(b=>b^k));
        if (/^[\x20-\x7e]+$/.test(x.toString('latin1'))) console.log(`  xor 0x${k.toString(16)}: ${x.toString('latin1')}`);
      }
    }
  }
})();
