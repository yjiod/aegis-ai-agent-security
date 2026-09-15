/**
 * lib/credentials.ts — 控制台本地账号凭据的哈希与校验（4A · 凭据生命周期）。
 *
 * 此前 change-password 只校验不持久化（worker 环境 env 只读），弹窗却谎称已改。
 * 现在把新密码以 PBKDF2-SHA256 哈希持久化到 PG settings 表（见 pg-store
 * pgGetCredential/pgSetCredential），登录时优先校验持久化哈希、无哈希则回落
 * env AEGIS_CONSOLE_PASSWORD（fail-safe：PG 不可用不影响既有登录）。
 *
 * 算法选择：workerd 提供 WebCrypto（crypto.subtle），用 PBKDF2-SHA256
 * （150k 迭代、16B 随机盐、256bit 输出），不依赖 node:crypto 的 scrypt
 * （workerd nodejs_compat 不保证提供）。校验用 node:crypto timingSafeEqual
 * 常数时间比较，防时序侧信道。
 *
 * 存储格式：`pbkdf2-sha256$<iterations>$<saltHex>$<dkHex>`（自描述，便于将来升参）。
 */
import { timingSafeEqual } from 'node:crypto';
import { pgGetCredential, pgSetCredential } from '@/lib/pg-store';

const ALGO = 'pbkdf2-sha256';
const ITERATIONS = 150_000;
const SALT_BYTES = 16;
const KEY_BITS = 256;

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function fromHex(hex: string): Uint8Array | null {
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

async function derive(plain: string, salt: Uint8Array, iterations: number): Promise<Uint8Array> {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(plain), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: salt as BufferSource, iterations },
    key,
    KEY_BITS,
  );
  return new Uint8Array(bits);
}

/** 生成自描述哈希串 `pbkdf2-sha256$iter$saltHex$dkHex`。 */
export async function hashPassword(plain: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_BYTES));
  const dk = await derive(plain, salt, ITERATIONS);
  return `${ALGO}$${ITERATIONS}$${toHex(salt)}$${toHex(dk)}`;
}

/** 常数时间校验明文 against 自描述哈希串；格式不符/解析失败一律 false（fail closed）。 */
export async function verifyPassword(plain: string, stored: string): Promise<boolean> {
  const parts = stored.split('$');
  if (parts.length !== 4 || parts[0] !== ALGO) return false;
  const iterations = Number(parts[1]);
  if (!Number.isFinite(iterations) || iterations <= 0) return false;
  const salt = fromHex(parts[2]);
  const expected = fromHex(parts[3]);
  if (!salt || !expected) return false;
  const dk = await derive(plain, salt, iterations);
  if (dk.length !== expected.length) return false;
  return timingSafeEqual(dk, expected);
}

/** 读取某 subject 的持久化哈希；PG 未配置/不可达/无记录返回 null（调用方回落 env）。 */
export async function loadPasswordHash(subject: string): Promise<string | null> {
  try {
    return await pgGetCredential(subject);
  } catch {
    return null;
  }
}

/** 持久化某 subject 的新哈希；返回是否真的写入成功（供如实告知用户）。 */
export async function savePasswordHash(subject: string, plain: string): Promise<boolean> {
  try {
    const hash = await hashPassword(plain);
    return await pgSetCredential(subject, hash);
  } catch {
    return false;
  }
}
