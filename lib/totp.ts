/**
 * lib/totp.ts — RFC 6238 TOTP（两步验证）原语（4A · Authentication）。
 *
 * 实现要点：
 *  - 密钥：20 字节随机（crypto.getRandomValues），base32(RFC4648, 无填充) 编码，
 *    与主流 authenticator App（Google/Microsoft Authenticator、1Password）互通。
 *  - 算法：HMAC-SHA1 + 动态截断，6 位数字，30s 步长（RFC 6238 默认）。
 *  - 校验允许 ±1 步时间窗（容忍客户端时钟漂移），常数时间比较防时序侧信道。
 *  - 仅用 WebCrypto/node:crypto 中 workerd 保证提供的能力（crypto.subtle HMAC-SHA1）。
 *
 * 存储：base32 密钥存 PG settings 表（见 pg-store pgGetMfa/pgSetMfa），服务端访问控制。
 */

const STEP_SECONDS = 30;
const DIGITS = 6;
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export function base32Decode(input: string): Uint8Array | null {
  const clean = input.replace(/=+$/g, '').replace(/\s/g, '').toUpperCase();
  if (clean.length === 0) return null;
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) return null;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  return Uint8Array.from(out);
}

/** 生成 20 字节随机密钥的 base32 表示。 */
export function generateTotpSecret(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return base32Encode(bytes);
}

/** 计算给定计数器（时间步）的 6 位 TOTP 码。 */
async function totpAt(secretBase32: string, counter: number): Promise<string | null> {
  const key = base32Decode(secretBase32);
  if (!key || key.length === 0) return null;
  // 8 字节大端计数器
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const cryptoKey = await crypto.subtle.importKey('raw', key as BufferSource, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, msg as BufferSource));
  const offset = sig[sig.length - 1] & 0x0f;
  const code =
    (((sig[offset] & 0x7f) << 24) |
      ((sig[offset + 1] & 0xff) << 16) |
      ((sig[offset + 2] & 0xff) << 8) |
      (sig[offset + 3] & 0xff)) %
    10 ** DIGITS;
  return String(code).padStart(DIGITS, '0');
}

/** 当前时间步的码（用于自测/展示）。 */
export async function currentTotp(secretBase32: string): Promise<string | null> {
  return totpAt(secretBase32, Math.floor(Date.now() / 1000 / STEP_SECONDS));
}

/**
 * 校验用户提交的码：允许 ±window 步（默认 1）。常数时间比较。
 * 返回 true 仅当码在当前窗内匹配。
 */
export async function verifyTotp(secretBase32: string, code: string, window = 1): Promise<boolean> {
  const submitted = (code ?? '').trim();
  if (!/^\d{6}$/.test(submitted)) return false;
  const counter = Math.floor(Date.now() / 1000 / STEP_SECONDS);
  for (let drift = -window; drift <= window; drift++) {
    const expected = await totpAt(secretBase32, counter + drift);
    if (expected === null) return false;
    // 常数时间比较（等长数字串）
    let diff = 0;
    for (let i = 0; i < expected.length; i++) diff |= expected.charCodeAt(i) ^ submitted.charCodeAt(i);
    if (diff === 0) return true;
  }
  return false;
}

/** otpauth:// URI（供 authenticator App 扫码/手动添加）。 */
export function otpauthUri(secretBase32: string, subject: string, issuer = 'Aegis'): string {
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(subject)}`;
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=${DIGITS}&period=${STEP_SECONDS}`;
}
