/**
 * @fileoverview 酷我音乐加密工具模块
 *
 * 严格遵守 REVERSE_SPEC.md 约束：
 * - 仅实现压缩包中确认存在的加密函数
 * - 未确认的算法标注 [算法未确认]，不推测实现
 *
 * 压缩包确认的加密函数（来源：KwLib.dll 导出表）：
 * - CMD5 类（MD5 哈希）—— ??0CMD5@@QAE@PBD@Z 等构造函数确认
 * - Base64 类（编解码）—— ?Base64Encode@Base64@KwLib@@ 确认
 * - Entrypt::Encrypt/Decrypt —— ?Encrypt@Entrypt@KwLib@@YAXPADHH@Z 确认
 *   [算法未确认] 具体算法和密钥来源未知，禁止推测
 * - Sig::CalcSign —— ?CalcSign@Sig@KwLib@@YA_NPBDPAI1@Z 确认
 *   [算法未确认] 输出两个 uint，具体算法未知
 *
 * 压缩包确认的字符串常量：
 * - yeelion / yeelion-kuwo-tme / yeelion_history / yeelion_rand
 * - KoOtOiTvINGwd (13字符，密钥候选)
 * - _Y8g2E6n0E1i7L5t2IoOoNk (24字符，密钥候选)
 *
 * 压缩包中不存在的（禁止实现）：
 * - RSA 公钥（压缩包无酷我自有公钥，已移除）
 *
 * @module crypto
 * @see REVERSE_SPEC.md 第四章
 */

const CryptoJS = require('crypto-js');

// ============================================================
// 压缩包确认的字符串常量（来源：strings 提取）
// ============================================================

/** Yeelion 签名/加密标识（来源：多个 DLL 确认） */
const YEELION = 'yeelion';

/** Yeelion TME 标识，与 .kwm 格式相关（来源：KwLib.dll） */
const YEELION_KUWO_TME = 'yeelion-kuwo-tme';

/** 历史记录加密标识（来源：KwMusicDLL.dll，与 _LoadHistory 相关） */
const YEELION_HISTORY = 'yeelion_history';

/** 随机数加密标识（来源：KwMusicDLL.dll，与搜索URL生成相关） */
const YEELION_RAND = 'yeelion_rand';

/** 密钥候选 1，13字符（来源：KwLib.dll/KwMV.dll/KwMusicDLL.dll/PlayerCore.dll/lidx.dll） */
const KEY_CANDIDATE_1 = 'KoOtOiTvINGwd';

/** 密钥候选 2，24字符（来源：KwLib.dll/KwMV.dll/KwMusicDLL.dll/PlayerCore.dll/lidx.dll） */
const KEY_CANDIDATE_2 = '_Y8g2E6n0E1i7L5t2IoOoNk';

/**
 * 登录加密盐值（来源：KwMusicDLL.dll 登录参数区域）
 *
 * 在 strings 输出中位于登录参数模板之间：
 *   from=pc&dev_id=
 *   kw@#d09b          <-- 本常量
 *   nSession = %d, nCode = %d
 *
 * 与 encryptlogin（加密登录标识）同区域，疑似密码加密盐值。
 * [用途未确认] 具体参与 MD5 还是 Entrypt::Encrypt 未知，禁止推测。
 */
const LOGIN_SALT = 'kw@#d09b';

// ============================================================
// UTF-8 编解码辅助
// ============================================================

function encodeUtf8(str) {
  if (typeof TextEncoder !== 'undefined') {
    return new TextEncoder().encode(str);
  }
  return new Uint8Array(Buffer.from(str, 'utf8'));
}

function decodeUtf8(uint8) {
  if (typeof TextDecoder !== 'undefined') {
    return new TextDecoder().decode(uint8);
  }
  return Buffer.from(uint8).toString('utf8');
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

// ============================================================
// MD5 哈希（对应压缩包 CMD5 类）
// 来源：KwLib.dll ??0CMD5@@QAE@PBD@Z 等构造函数确认
// ============================================================

/**
 * MD5 哈希计算
 *
 * 对应压缩包 KwLib.dll 中的 CMD5 类：
 * - ??0CMD5@@QAE@XZ (默认构造)
 * - ??0CMD5@@QAE@PBD@Z (const char* 构造)
 * - ??0CMD5@@QAE@PAK@Z (unsigned long* 构造)
 *
 * @param {string|Object} data - 待哈希的数据
 * @returns {string} 32位十六进制 MD5 值
 */
function cryptoMd5(data) {
  const buffer = typeof data === 'object' ? JSON.stringify(data) : data;
  return CryptoJS.MD5(buffer).toString(CryptoJS.enc.Hex);
}

// ============================================================
// Base64 编解码（对应压缩包 Base64 类）
// 来源：KwLib.dll ?Base64Encode@Base64@KwLib@@ / ?Base64Decode@Base64@KwLib@@
// ============================================================

/**
 * Base64 编码
 *
 * 对应压缩包 KwLib.dll 中的 Base64::Base64Encode
 * 压缩包日志确认："Encryption YL_Base64Encode in/out"（YL=Yeelion）
 *
 * @param {string|Uint8Array} data - 待编码数据
 * @returns {string} Base64 字符串
 */
function base64Encode(data) {
  if (data instanceof Uint8Array) {
    return CryptoJS.enc.Base64.stringify(wordArrayFromBuffer(data));
  }
  return CryptoJS.enc.Base64.stringify(CryptoJS.enc.Utf8.parse(data));
}

/**
 * Base64 解码
 *
 * 对应压缩包 KwLib.dll 中的 Base64::Base64Decode
 *
 * @param {string} base64Str - Base64 字符串
 * @returns {string} 解码后的字符串
 */
function base64Decode(base64Str) {
  const words = CryptoJS.enc.Base64.parse(base64Str);
  return decodeUtf8(wordArrayToBuffer(words));
}

// ============================================================
// Entrypt 加密/解密
// 来源：KwLib.dll ?Encrypt@Entrypt@KwLib@@YAXPADHH@Z / ?Decrypt@Entrypt@KwLib@@YAXPADHH@Z
// [算法未确认] 具体加密算法和密钥来源未知，禁止推测实现
// ============================================================

/**
 * [算法未确认] Entrypt 加密
 *
 * 压缩包函数签名：void Entrypt::Encrypt(char* data, int len, int mode)
 *
 * ⚠️ 警告：此函数的具体加密算法、密钥来源在压缩包中未逆向确认。
 * 禁止用推测的 AES/DES 实现冒充。需要反汇编 KwLib.dll 确认后才能实现。
 *
 * @throws {Error} 调用时抛出错误，提示需要人工逆向确认
 */
function entryptEncrypt(data, len, mode) {
  throw new Error(
    '[算法未确认] Entrypt::Encrypt 的具体算法需要反汇编 KwLib.dll 确认。' +
      '压缩包只确认了函数签名 void Encrypt(char*, int, int)，' +
      '未确认密钥来源和加密类型。请参考 REVERSE_SPEC.md 第四章和第七章。'
  );
}

/**
 * [算法未确认] Entrypt 解密
 *
 * 压缩包函数签名：void Entrypt::Decrypt(char* data, int len, int mode)
 *
 * ⚠️ 警告：同 entryptEncrypt，算法未确认。
 *
 * @throws {Error} 调用时抛出错误，提示需要人工逆向确认
 */
function entryptDecrypt(data, len, mode) {
  throw new Error(
    '[算法未确认] Entrypt::Decrypt 的具体算法需要反汇编 KwLib.dll 确认。' +
      '压缩包只确认了函数签名 void Decrypt(char*, int, int)，' +
      '未确认密钥来源和加密类型。请参考 REVERSE_SPEC.md 第四章和第七章。'
  );
}

// ============================================================
// Sig::CalcSign 签名计算
// 来源：KwLib.dll ?CalcSign@Sig@KwLib@@YA_NPBDPAI1@Z
// [算法未确认] 输出两个 uint，具体算法未知
// ============================================================

/**
 * [算法未确认] CalcSign 签名计算
 *
 * 压缩包函数签名：bool Sig::CalcSign(const char* data, unsigned int* out1, unsigned int* out2)
 *
 * ⚠️ 警告：此函数的具体算法在压缩包中未逆向确认。
 * 已知信息：
 * - 输入：const char* data（字符串）
 * - 输出：两个 unsigned int* out1, out2（两个无符号整数）
 * - 用于 stype=geturl&sign=%s 等接口的 sign 参数
 *
 * 未知信息（禁止推测）：
 * - 两个 uint 如何拼成 sign 字符串（hex？decimal？拼接顺序？）
 * - 是否使用 yeelion 作为盐值
 * - 内部是否调用 CMD5
 *
 * @throws {Error} 调用时抛出错误，提示需要人工逆向确认
 */
function calcSign(data) {
  throw new Error(
    '[算法未确认] Sig::CalcSign 的具体算法需要反汇编 KwLib.dll 确认。' +
      '压缩包只确认了函数签名 bool CalcSign(const char*, unsigned int*, unsigned int*)，' +
      '输出两个 uint 的拼接方式未知。请参考 REVERSE_SPEC.md 第四章和第七章。'
  );
}

module.exports = {
  // 压缩包确认的字符串常量
  YEELION,
  YEELION_KUWO_TME,
  YEELION_HISTORY,
  YEELION_RAND,
  KEY_CANDIDATE_1,
  KEY_CANDIDATE_2,
  LOGIN_SALT,

  // 压缩包确认的加密函数（已实现）
  cryptoMd5,
  base64Encode,
  base64Decode,

  // 压缩包确认存在但算法未确认的函数（空壳，调用即抛错）
  entryptEncrypt,
  entryptDecrypt,
  calcSign,
};
