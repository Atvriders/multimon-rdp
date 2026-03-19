/**
 * Pure-JS MD4 (RFC 1320)
 * OpenSSL 3 removed MD4 from default providers; Node 18+ throws on
 * crypto.createHash('md4').  We implement it here instead.
 * Used by NTLM to produce the NT hash: MD4(UTF-16LE(password))
 */

function rl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}
const add = (...v: number[]) => v.reduce((a, b) => (a + b) >>> 0, 0);
const F = (x: number, y: number, z: number) => ((x & y) | (~x & z)) >>> 0;
const G = (x: number, y: number, z: number) => ((x & y) | (x & z) | (y & z)) >>> 0;
const H = (x: number, y: number, z: number) => (x ^ y ^ z) >>> 0;

export function md4(input: Buffer): Buffer {
  const len = input.length;
  // Pad: append 0x80, zeros, then 64-bit LE bit-length
  const padLen = len % 64 < 56 ? 56 - (len % 64) : 120 - (len % 64);
  const m = Buffer.alloc(len + padLen + 8);
  input.copy(m);
  m[len] = 0x80;
  const bits = len * 8;
  m.writeUInt32LE(bits >>> 0,                       len + padLen);
  m.writeUInt32LE(Math.floor(bits / 0x100000000),   len + padLen + 4);

  let a = 0x67452301, b = 0xEFCDAB89, c = 0x98BADCFE, d = 0x10325476;

  for (let i = 0; i < m.length; i += 64) {
    const X: number[] = [];
    for (let j = 0; j < 16; j++) X.push(m.readUInt32LE(i + j * 4));
    let [A, B, C, D] = [a, b, c, d];

    // Round 1
    for (const [i0, s] of [[0,3],[1,7],[2,11],[3,19],[4,3],[5,7],[6,11],[7,19],
                            [8,3],[9,7],[10,11],[11,19],[12,3],[13,7],[14,11],[15,19]]) {
      A = rl(add(A, F(B,C,D), X[i0]),           s as number);
      [A,B,C,D] = [D,A,B,C];
    }
    // Round 2
    for (const [i0, s] of [[0,3],[4,5],[8,9],[12,13],[1,3],[5,5],[9,9],[13,13],
                            [2,3],[6,5],[10,9],[14,13],[3,3],[7,5],[11,9],[15,13]]) {
      A = rl(add(A, G(B,C,D), X[i0], 0x5A827999), s as number);
      [A,B,C,D] = [D,A,B,C];
    }
    // Round 3
    for (const [i0, s] of [[0,3],[8,9],[4,11],[12,15],[2,3],[10,9],[6,11],[14,15],
                            [1,3],[9,9],[5,11],[13,15],[3,3],[11,9],[7,11],[15,15]]) {
      A = rl(add(A, H(B,C,D), X[i0], 0x6ED9EBA1), s as number);
      [A,B,C,D] = [D,A,B,C];
    }

    a = add(a, A); b = add(b, B); c = add(c, C); d = add(d, D);
  }

  const out = Buffer.alloc(16);
  out.writeUInt32LE(a, 0); out.writeUInt32LE(b, 4);
  out.writeUInt32LE(c, 8); out.writeUInt32LE(d, 12);
  return out;
}
