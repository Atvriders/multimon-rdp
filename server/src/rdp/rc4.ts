/**
 * Pure-JS RC4 (ARCFOUR) stream cipher.
 * OpenSSL 3 moved RC4 to the legacy provider, which is disabled in Node 18+
 * Alpine images. Used by NTLM sealing (CredSSP) to encrypt the session key
 * and to produce pubKeyAuth / authInfo tokens.
 */

export class RC4 {
  private S: Uint8Array;
  private i = 0;
  private j = 0;

  constructor(key: Buffer) {
    this.S = new Uint8Array(256);
    for (let n = 0; n < 256; n++) this.S[n] = n;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + this.S[i] + key[i % key.length]) & 0xff;
      const tmp = this.S[i]; this.S[i] = this.S[j]; this.S[j] = tmp;
    }
  }

  update(data: Buffer): Buffer {
    const S   = this.S;
    const out = Buffer.alloc(data.length);
    let { i, j } = this;
    for (let k = 0; k < data.length; k++) {
      i = (i + 1) & 0xff;
      j = (j + S[i]) & 0xff;
      const tmp = S[i]; S[i] = S[j]; S[j] = tmp;
      out[k] = data[k] ^ S[(S[i] + S[j]) & 0xff];
    }
    this.i = i;
    this.j = j;
    return out;
  }
}
