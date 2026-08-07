const CryptoJS = require('crypto-js');
const forge = require('node-forge');
const { randomString } = require('./util');

const publicRsaKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDIAG7QOELSYoIJvTFJhMpe1s/gbjDJX51HBNnEl5HXqTW6lQ7LC8jr9fWZTwusknp+sVGzwd40MwP6U5yDE27M/X1+UR4tvOGOqp94TJtQ1EPnWGWXngpeIW5GxoQGao1rmYWAu6oi1z9XkChrsUdC6DJE5E221wf/4WLFxwAtRQIDAQAB
-----END PUBLIC KEY-----`;

const rsaKeyCache = new Map();

function encodeUtf8(str) {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(str);
  }
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(str, 'utf8'));
  }
  const codePoints = [];
  for (let i = 0; i < str.length; i++) {
    let code = str.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff && i + 1 < str.length) {
      const next = str.charCodeAt(i + 1);
      if (next >= 0xdc00 && next <= 0xdfff) {
        code = ((code - 0xd800) << 10) + (next - 0xdc00) + 0x10000;
        i++;
      }
    }
    codePoints.push(code);
  }
  const bytes = [];
  for (const code of codePoints) {
    if (code <= 0x7f) {
      bytes.push(code);
    } else if (code <= 0x7ff) {
      bytes.push(0xc0 | (code >> 6), 0x80 | (code & 0x3f));
    } else if (code <= 0xffff) {
      bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    } else {
      bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 0x3f), 0x80 | ((code >> 6) & 0x3f), 0x80 | (code & 0x3f));
    }
  }
  return new Uint8Array(bytes);
}

function decodeUtf8(uint8) {
  if (typeof TextDecoder !== 'undefined') {
    return new TextDecoder().decode(uint8);
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(uint8).toString('utf8');
  }
  let out = '';
  let i = 0;
  while (i < uint8.length) {
    const byte1 = uint8[i++];
    if (byte1 < 0x80) {
      out += String.fromCharCode(byte1);
      continue;
    }
    if (byte1 < 0xe0) {
      const byte2 = uint8[i++] & 0x3f;
      const codePoint = ((byte1 & 0x1f) << 6) | byte2;
      out += String.fromCharCode(codePoint);
      continue;
    }
    if (byte1 < 0xf0) {
      const byte2 = uint8[i++] & 0x3f;
      const byte3 = uint8[i++] & 0x3f;
      const codePoint = ((byte1 & 0x0f) << 12) | (byte2 << 6) | byte3;
      out += String.fromCharCode(codePoint);
      continue;
    }
    const byte2 = uint8[i++] & 0x3f;
    const byte3 = uint8[i++] & 0x3f;
    const byte4 = uint8[i++] & 0x3f;
    let codePoint = ((byte1 & 0x07) << 18) | (byte2 << 12) | (byte3 << 6) | byte4;
    codePoint -= 0x10000;
    out += String.fromCharCode((codePoint >> 10) + 0xd800, (codePoint & 0x3ff) + 0xdc00);
  }
  return out;
}

function normalizeBuffer(data) {
  if (data instanceof Uint8Array) return data;
  const str = typeof data === 'string' ? data : JSON.stringify(data);
  return encodeUtf8(str);
}

function wordArrayFromBuffer(uint8) {
  const words = [];
  for (let i = 0; i < uint8.length; i += 4) {
    words.push(
      ((uint8[i] || 0) << 24) | ((uint8[i + 1] || 0) << 16) | ((uint8[i + 2] || 0) << 8) | (uint8[i + 3] || 0)
    );
  }
  return CryptoJS.lib.WordArray.create(words, uint8.length);
}

function wordArrayToBuffer(wordArray) {
  const { words, sigBytes } = wordArray;
  const uint8 = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i++) {
    uint8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return uint8;
}

function getForgePublicKey(pem) {
  if (!rsaKeyCache.has(pem)) {
    rsaKeyCache.set(pem, forge.pki.publicKeyFromPem(pem));
  }
  return rsaKeyCache.get(pem);
}

function bufferToBinaryString(buffer) {
  let out = '';
  for (let i = 0; i < buffer.length; i++) out += String.fromCharCode(buffer[i]);
  return out;
}

/**
 * MD5 加密
 */
function cryptoMd5(data) {
  const buffer = typeof data === 'object' ? JSON.stringify(data) : data;
  return CryptoJS.MD5(buffer).toString(CryptoJS.enc.Hex);
}

/**
 * Sha1 加密
 */
function cryptoSha1(data) {
  const buffer = typeof data === 'object' ? JSON.stringify(data) : data;
  return CryptoJS.SHA1(buffer).toString(CryptoJS.enc.Hex);
}

/**
 * AES 加密
 */
function cryptoAesEncrypt(data, opt) {
  if (typeof data === 'object') data = JSON.stringify(data);
  const buffer = normalizeBuffer(data);
  let key;
  let iv;
  let tempKey = '';

  if (opt?.key && opt?.iv) {
    key = opt.key;
    iv = opt.iv;
  } else {
    tempKey = opt?.key || randomString(16).toLowerCase();
    key = cryptoMd5(tempKey).substring(0, 32);
    iv = key.substring(key.length - 16);
  }

  const encrypted = CryptoJS.AES.encrypt(wordArrayFromBuffer(buffer), CryptoJS.enc.Utf8.parse(key), {
    iv: CryptoJS.enc.Utf8.parse(iv),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const hex = CryptoJS.enc.Hex.stringify(encrypted.ciphertext);
  if (opt?.key && opt?.iv) return hex;
  return { str: hex, key: tempKey };
}

/**
 * AES 解密
 */
function cryptoAesDecrypt(data, key, iv) {
  if (!iv) key = cryptoMd5(key).substring(0, 32);
  iv = iv || key.substring(key.length - 16);
  const cipherParams = CryptoJS.lib.CipherParams.create({ ciphertext: CryptoJS.enc.Hex.parse(data) });

  const decrypted = CryptoJS.AES.decrypt(cipherParams, CryptoJS.enc.Utf8.parse(key), {
    iv: CryptoJS.enc.Utf8.parse(iv),
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7,
  });

  const text = decodeUtf8(wordArrayToBuffer(decrypted));
  try {
    return JSON.parse(text);
  } catch (e) {
    return text;
  }
}

/**
 * RSA加密
 */
function cryptoRSAEncrypt(data, publicKey) {
  const buffer = normalizeBuffer(data);
  const pem = publicKey || publicRsaKey;
  const key = getForgePublicKey(pem);
  const keyLength = Math.ceil(key.n.bitLength() / 8);

  if (buffer.length > keyLength) throw new Error('Data length exceeds key size');
  let padded = buffer;
  if (buffer.length < keyLength) {
    padded = new Uint8Array(keyLength);
    padded.set(buffer);
  }

  const encrypted = key.encrypt(bufferToBinaryString(padded), 'RSAES-PKCS1-V1_5');
  return forge.util.bytesToHex(encrypted);
}

/**
 * 酷我音乐网页端 Secret 生成算法
 *
 * 基于 cookie `Hm_Iuvt_cdb524f42f23cer9b268564v7y735ewrq2324` 的值，
 * 通过线性同余生成器(LCG) + XOR 运算生成请求头 Secret。
 *
 * 算法步骤：
 * 1. 将 cookie key 每个字符的 charCode 拼接成数字字符串 n
 * 2. 从 n 中按位置 o,2o,3o,4o,5o 提取数字组成乘数 r
 * 3. 生成随机数 d，将 n 折叠到 10 位以内
 * 4. 用 LCG (n = (r*n+c) % l) 逐字符 XOR cookie value
 * 5. 拼接十六进制结果 + d
 *
 * @param {string} cookieValue - Hm_Iuvt_cdb524f42f23cer9b268564v7y735ewrq2324 cookie 的值
 * @param {string} hmKey - cookie key，默认使用内置常量
 * @returns {string} Secret 字符串
 */
function generateKuwoSecret(cookieValue, hmKey) {
  const e = hmKey || require('./config.json').hmCookie;
  const t = cookieValue || '';

  if (!e || e.length <= 0) return null;

  let n = '';
  for (let i = 0; i < e.length; i++) {
    n += e.charCodeAt(i).toString();
  }

  const o = Math.floor(n.length / 5);
  const r = parseInt(n.charAt(o) + n.charAt(2 * o) + n.charAt(3 * o) + n.charAt(4 * o) + n.charAt(5 * o));
  const c = Math.ceil(e.length / 2);
  const l = Math.pow(2, 31) - 1;

  if (r < 2) return null;

  let d = Math.round(1e9 * Math.random()) % 1e8;
  n += d;
  while (n.length > 10) {
    n = (parseInt(n.substring(0, 10)) + parseInt(n.substring(10, n.length))).toString();
  }
  n = (r * n + c) % l;

  let f = '';
  let h = '';
  for (let i = 0; i < t.length; i++) {
    f = parseInt(t.charCodeAt(i) ^ Math.floor((n / l) * 255));
    h += f < 16 ? '0' + f.toString(16) : f.toString(16);
    n = (r * n + c) % l;
  }

  d = d.toString(16);
  while (d.length < 8) {
    d = '0' + d;
  }

  return h + d;
}

/**
 * 生成酷我网页端请求 ID (reqId)
 *
 * 格式：{12位hex时间戳}-{4}-{4}-{4}-{8}
 *
 * @returns {string} reqId
 */
function generateReqId() {
  const timestamp = Date.now().toString(16).padStart(12, '0');
  const random = Array.from({ length: 20 }, () => Math.floor(Math.random() * 16).toString(16)).join('');
  return `${timestamp}-${random.substring(0, 4)}-${random.substring(4, 8)}-${random.substring(8, 12)}-${random.substring(12)}`;
}

module.exports = {
  cryptoAesDecrypt,
  cryptoAesEncrypt,
  cryptoMd5,
  cryptoRSAEncrypt,
  cryptoSha1,
  publicRsaKey,
  wordArrayFromBuffer,
  generateKuwoSecret,
  generateReqId,
};
