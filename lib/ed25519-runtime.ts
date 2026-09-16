/**
 * lib/ed25519-runtime.ts — Ed25519（RFC8032）签名/验签，**运行时原生实现**，无手写曲线数学。
 *
 * 为什么不用纯 JS 曲线实现：手写 bigint 曲线极易出隐蔽错误（本项目曾踩坑并以
 * OpenSSL 向量证伪），密码学原语必须用经过审计的原生实现。
 *
 * 运行时特征探测（批3 dual-sign）：
 *   1) WebCrypto（workerd/Cloudflare 与较新浏览器/Node 支持 Ed25519）：
 *      importKey('pkcs8') 私钥 → exportKey('jwk') 取 x=公钥；subtle.sign/verify。
 *   2) node:crypto（本地 dev/SSR node 运行时）：createPrivateKey/createPublicKey/sign/verify。
 *   3) 均不可用 → 返回 null / false（调用方回落 HMAC-only，dual-sign 优雅关闭）。
 *
 * 私钥形态：32B seed；PKCS#8 DER 前缀固定 302e020100300506032b657004220420。
 */

const PKCS8_PREFIX = '302e020100300506032b657004220420';

function seedToPkcs8(seed: Uint8Array): Uint8Array {
  const prefix = hexToBytes(PKCS8_PREFIX);
  const out = new Uint8Array(prefix.length + seed.length);
  out.set(prefix, 0);
  out.set(seed, prefix.length);
  return out;
}
function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export function bytesToB64(bytes: Uint8Array): string {
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
export function b64ToBytes(s: string): Uint8Array | null {
  try {
    const clean = s.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(clean);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

type Backend = 'webcrypto' | 'node' | null;
let detected: Backend | undefined;

async function detect(): Promise<Backend> {
  if (detected !== undefined) return detected;
  // probe with a throwaway seed
  const seed = new Uint8Array(32).fill(7);
  if (await webcryptoSign(seed, new Uint8Array([1])) !== null) detected = 'webcrypto';
  else if ((await nodeSign(seed, new Uint8Array([1]))) !== null) detected = 'node';
  else detected = null;
  return detected;
}

async function webcryptoSign(seed: Uint8Array, msg: Uint8Array): Promise<Uint8Array | null> {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) return null;
  try {
    const priv = await subtle.importKey('pkcs8', seedToPkcs8(seed) as BufferSource, { name: 'Ed25519' }, false, ['sign']);
    const sig = await subtle.sign('Ed25519', priv, msg as BufferSource);
    return new Uint8Array(sig);
  } catch {
    return null;
  }
}
async function webcryptoPublic(seed: Uint8Array): Promise<Uint8Array | null> {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) return null;
  try {
    const priv = await subtle.importKey('pkcs8', seedToPkcs8(seed) as BufferSource, { name: 'Ed25519' }, true, ['sign']);
    const jwk = await subtle.exportKey('jwk', priv);
    const x = (jwk as { x?: string }).x;
    if (!x) return null;
    return b64ToBytes(x);
  } catch {
    return null;
  }
}
async function webcryptoVerify(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean | null> {
  const subtle = (globalThis as { crypto?: Crypto }).crypto?.subtle;
  if (!subtle) return null;
  try {
    const key = await subtle.importKey('raw', pub as BufferSource, { name: 'Ed25519' }, false, ['verify']);
    return await subtle.verify('Ed25519', key, sig as BufferSource, msg as BufferSource);
  } catch {
    return null;
  }
}

type NodeCrypto = typeof import('node:crypto');
let nodeCryptoPromise: Promise<NodeCrypto | null> | undefined;
function nodeCrypto(): Promise<NodeCrypto | null> {
  if (!nodeCryptoPromise) {
    nodeCryptoPromise = import('node:crypto').then((m) => m as NodeCrypto).catch(() => null);
  }
  return nodeCryptoPromise;
}
async function nodeSign(seed: Uint8Array, msg: Uint8Array): Promise<Uint8Array | null> {
  const c = await nodeCrypto();
  if (!c) return null;
  try {
    const priv = c.createPrivateKey({ key: Buffer.from(seedToPkcs8(seed)), format: 'der', type: 'pkcs8' });
    return new Uint8Array(c.sign(null, Buffer.from(msg), priv));
  } catch {
    return null;
  }
}
async function nodePublic(seed: Uint8Array): Promise<Uint8Array | null> {
  const c = await nodeCrypto();
  if (!c) return null;
  try {
    const priv = c.createPrivateKey({ key: Buffer.from(seedToPkcs8(seed)), format: 'der', type: 'pkcs8' });
    const pub = c.createPublicKey(priv);
    return new Uint8Array(pub.export({ type: 'spki', format: 'der' }).subarray(-32));
  } catch {
    return null;
  }
}
async function nodeVerify(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean | null> {
  const c = await nodeCrypto();
  if (!c) return null;
  try {
    const spki = Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(pub)]);
    const key = c.createPublicKey({ key: spki, format: 'der', type: 'spki' });
    return c.verify(null, Buffer.from(msg), key, Buffer.from(sig));
  } catch {
    return null;
  }
}

/** 当前运行时是否支持 Ed25519（不支持则 dual-sign 优雅关闭）。 */
export async function ed25519Supported(): Promise<boolean> {
  return (await detect()) !== null;
}
/** 由 32B seed 推导 32B 公钥；不支持返回 null。 */
export async function ed25519PublicKey(seed: Uint8Array): Promise<Uint8Array | null> {
  const backend = await detect();
  if (backend === 'webcrypto') return webcryptoPublic(seed);
  if (backend === 'node') return nodePublic(seed);
  return null;
}
/** Ed25519 签名（64B）；不支持返回 null。 */
export async function ed25519Sign(seed: Uint8Array, msg: Uint8Array): Promise<Uint8Array | null> {
  const backend = await detect();
  if (backend === 'webcrypto') return webcryptoSign(seed, msg);
  if (backend === 'node') return nodeSign(seed, msg);
  return null;
}
/** Ed25519 验签；不支持返回 null（调用方据此回落）。 */
export async function ed25519Verify(pub: Uint8Array, msg: Uint8Array, sig: Uint8Array): Promise<boolean | null> {
  const backend = await detect();
  if (backend === 'webcrypto') return webcryptoVerify(pub, msg, sig);
  if (backend === 'node') return nodeVerify(pub, msg, sig);
  return null;
}
