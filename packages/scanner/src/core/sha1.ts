/**
 * Pure SHA-1 (hex digest of the UTF-8 encoding of `message`).
 * C4: the browser bundle must compute finding ids byte-identically to the
 * CLI without node:crypto, so the core uses this implementation everywhere.
 * Correctness is pinned against node:crypto in test/core-id.test.ts.
 */
export function sha1Hex(message: string): string {
  const bytes = new TextEncoder().encode(message);
  const h0 = 0x67452301;
  const h1 = 0xefcdab89;
  const h2 = 0x98badcfe;
  const h3 = 0x10325476;
  const h4 = 0xc3d2e1f0;
  const ml = bytes.length;
  const withPadding = ml + 9;
  const blocks = Math.ceil(withPadding / 64);
  const words = new Uint32Array(blocks * 16);
  for (let i = 0; i < ml; i++) {
    const byte = bytes[i] ?? 0;
    words[i >> 2] = (words[i >> 2] ?? 0) | (byte << ((3 - (i % 4)) * 8));
  }
  words[ml >> 2] = (words[ml >> 2] ?? 0) | (0x80 << ((3 - (ml % 4)) * 8));
  const bitLenHi = Math.floor((ml * 8) / 0x100000000);
  const bitLenLo = (ml * 8) >>> 0;
  words[blocks * 16 - 2] = bitLenHi;
  words[blocks * 16 - 1] = bitLenLo;

  let a = h0,
    b = h1,
    c = h2,
    d = h3,
    e = h4;
  const w = new Uint32Array(80);
  for (let block = 0; block < blocks; block++) {
    for (let i = 0; i < 16; i++) w[i] = words[block * 16 + i] ?? 0;
    for (let i = 16; i < 80; i++) {
      const p3 = w[i - 3] ?? 0;
      const p8 = w[i - 8] ?? 0;
      const p14 = w[i - 14] ?? 0;
      const p16 = w[i - 16] ?? 0;
      w[i] = rotl(p3 ^ p8 ^ p14 ^ p16, 1);
    }
    let aa = a,
      bb = b,
      cc = c,
      dd = d,
      ee = e;
    for (let i = 0; i < 80; i++) {
      let f: number, k: number;
      if (i < 20) {
        f = (bb & cc) | (~bb & dd);
        k = 0x5a827999;
      } else if (i < 40) {
        f = bb ^ cc ^ dd;
        k = 0x6ed9eba1;
      } else if (i < 60) {
        f = (bb & cc) | (bb & dd) | (cc & dd);
        k = 0x8f1bbcdc;
      } else {
        f = bb ^ cc ^ dd;
        k = 0xca62c1d6;
      }
      const wi = w[i] ?? 0;
      const temp = (rotl(aa, 5) + f + ee + k + wi) >>> 0;
      ee = dd;
      dd = cc;
      cc = rotl(bb, 30);
      bb = aa;
      aa = temp;
    }
    a = (a + aa) >>> 0;
    b = (b + bb) >>> 0;
    c = (c + cc) >>> 0;
    d = (d + dd) >>> 0;
    e = (e + ee) >>> 0;
  }
  return [a, b, c, d, e].map((x) => x.toString(16).padStart(8, "0")).join("");
}

function rotl(x: number, n: number): number {
  return ((x << n) | (x >>> (32 - n))) >>> 0;
}
