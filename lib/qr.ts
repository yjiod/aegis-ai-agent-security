/**
 * QR 渲染封装：基于 vendored 的 Project Nayuki QR Code generator（MIT，见 lib/qrcodegen.ts）。
 * 用于把 otpauth:// TOTP URI 渲染成可被任意 authenticator 扫描的 SVG。
 * EC 级别 M；mask 由编码器按规范自动选优。
 */
import { QrCode } from './qrcodegen';

export function qrMatrix(text: string): boolean[][] {
  const qr = QrCode.encodeText(text, QrCode.Ecc.MEDIUM);
  const n = qr.size;
  const m: boolean[][] = [];
  for (let y = 0; y < n; y += 1) {
    const row: boolean[] = [];
    for (let x = 0; x < n; x += 1) row.push(qr.getModule(x, y));
    m.push(row);
  }
  return m;
}

/** 渲染为 SVG 字符串（含 quiet zone，白底黑模块，crispEdges 保证扫码锐利）。 */
export function qrSvg(text: string, scale = 4, margin = 4): string {
  const m = qrMatrix(text);
  const n = m.length;
  const dim = (n + margin * 2) * scale;
  const rects: string[] = [];
  for (let r = 0; r < n; r += 1) {
    for (let c = 0; c < n; c += 1) {
      if (m[r][c]) {
        rects.push(`<rect x="${(c + margin) * scale}" y="${(r + margin) * scale}" width="${scale}" height="${scale}"/>`);
      }
    }
  }
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${dim} ${dim}" width="${dim}" height="${dim}" shape-rendering="crispEdges"><rect width="${dim}" height="${dim}" fill="#ffffff"/><g fill="#000000">${rects.join('')}</g></svg>`;
}
