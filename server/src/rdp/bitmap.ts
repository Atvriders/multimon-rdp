/**
 * RDP bitmap update decoder.
 * Converts TS_FP_UPDATE_BITMAP / TS_UPDATE_BITMAP tile data into raw RGBA.
 */

export interface BitmapTile {
  x:      number;
  y:      number;
  width:  number;
  height: number;
  rgba:   Buffer;   // width*height*4 bytes, RGBA
}

// ── Parse Fast-Path bitmap update ────────────────────────────────────────

/**
 * Parse a FASTPATH_UPDATETYPE_BITMAP payload into individual tiles.
 * The payload starts immediately after the update-type byte.
 */
export function parseFpBitmap(payload: Buffer): BitmapTile[] {
  const tiles: BitmapTile[] = [];
  let off = 0;

  const count = payload.readUInt16LE(off); off += 2;

  for (let i = 0; i < count; i++) {
    if (off + 18 > payload.length) break;
    const destLeft   = payload.readUInt16LE(off);      off += 2;
    const destTop    = payload.readUInt16LE(off);      off += 2;
    const destRight  = payload.readUInt16LE(off);      off += 2;
    const destBottom = payload.readUInt16LE(off);      off += 2;
    const width      = payload.readUInt16LE(off);      off += 2;
    const height     = payload.readUInt16LE(off);      off += 2;
    const bpp        = payload.readUInt16LE(off);      off += 2;
    const flags      = payload.readUInt16LE(off);      off += 2;
    const bmpLen     = payload.readUInt16LE(off);      off += 2;

    if (off + bmpLen > payload.length) break;
    const bmpData = payload.slice(off, off + bmpLen); off += bmpLen;

    const tileW = destRight  - destLeft;
    const tileH = destBottom - destTop;
    if (tileW <= 0 || tileH <= 0) continue;

    const compressed = (flags & 0x0400) !== 0;
    let rgba: Buffer | null = null;

    if (compressed) {
      rgba = decompressRle(bmpData, tileW, tileH, bpp);
    } else {
      rgba = rawToRgba(bmpData, tileW, tileH, bpp);
    }

    if (rgba) {
      tiles.push({ x: destLeft, y: destTop, width: tileW, height: tileH, rgba });
    }
  }
  return tiles;
}

// ── Pixel format converters ───────────────────────────────────────────────

function rawToRgba(data: Buffer, w: number, h: number, bpp: number): Buffer {
  const rgba = Buffer.alloc(w * h * 4);
  const bytesPerPixel = Math.ceil(bpp / 8);
  // RDP bitmaps are stored bottom-up
  for (let row = 0; row < h; row++) {
    const srcRow = h - 1 - row;
    for (let col = 0; col < w; col++) {
      const srcOff = (srcRow * w + col) * bytesPerPixel;
      const dstOff = (row * w + col) * 4;
      pixelToRgba(data, srcOff, bpp, rgba, dstOff);
    }
  }
  return rgba;
}

function pixelToRgba(src: Buffer, srcOff: number, bpp: number, dst: Buffer, dstOff: number): void {
  switch (bpp) {
    case 32: {
      dst[dstOff]     = src[srcOff + 2]; // R
      dst[dstOff + 1] = src[srcOff + 1]; // G
      dst[dstOff + 2] = src[srcOff];     // B
      dst[dstOff + 3] = 255;
      break;
    }
    case 24: {
      dst[dstOff]     = src[srcOff + 2];
      dst[dstOff + 1] = src[srcOff + 1];
      dst[dstOff + 2] = src[srcOff];
      dst[dstOff + 3] = 255;
      break;
    }
    case 16: {
      const px = src.readUInt16LE(srcOff);
      dst[dstOff]     = ((px >> 11) & 0x1F) << 3;
      dst[dstOff + 1] = ((px >>  5) & 0x3F) << 2;
      dst[dstOff + 2] =  (px        & 0x1F) << 3;
      dst[dstOff + 3] = 255;
      break;
    }
    case 15: {
      const px = src.readUInt16LE(srcOff);
      dst[dstOff]     = ((px >> 10) & 0x1F) << 3;
      dst[dstOff + 1] = ((px >>  5) & 0x1F) << 3;
      dst[dstOff + 2] =  (px        & 0x1F) << 3;
      dst[dstOff + 3] = 255;
      break;
    }
    default: {
      // 8bpp etc. — just grey
      const v = src[srcOff] ?? 0;
      dst[dstOff] = v; dst[dstOff+1] = v; dst[dstOff+2] = v; dst[dstOff+3] = 255;
    }
  }
}

// ── RDP RLE Bitmap Decompressor (MS-RDPBCGR §3.1.8.1) ───────────────────

function decompressRle(data: Buffer, w: number, h: number, bpp: number): Buffer | null {
  // 16/24/32bpp RLE are the common cases; implement 16bpp and 24/32bpp
  if (bpp !== 32 && bpp !== 24 && bpp !== 16 && bpp !== 15) {
    return rawToRgba(data, w, h, bpp); // fallback
  }

  const bpp32 = (bpp === 32 || bpp === 24);
  const Bpp = bpp32 ? 3 : 2; // bytes per pixel in compressed stream

  const rgba  = Buffer.alloc(w * h * 4);
  const row   = Buffer.alloc(w * 4);
  let src     = 0;
  let dstRow  = h - 1; // bitmaps are bottom-up

  const writePixel = (pxBuf: Buffer, pxOff: number, dstBuf: Buffer, dstOff: number) => {
    if (bpp32) {
      dstBuf[dstOff]     = pxBuf[pxOff + 2];
      dstBuf[dstOff + 1] = pxBuf[pxOff + 1];
      dstBuf[dstOff + 2] = pxBuf[pxOff];
      dstBuf[dstOff + 3] = 255;
    } else {
      const px = pxBuf.readUInt16LE(pxOff);
      if (bpp === 16) {
        dstBuf[dstOff]     = ((px >> 11) & 0x1F) << 3;
        dstBuf[dstOff + 1] = ((px >>  5) & 0x3F) << 2;
        dstBuf[dstOff + 2] =  (px        & 0x1F) << 3;
      } else { // 15bpp
        dstBuf[dstOff]     = ((px >> 10) & 0x1F) << 3;
        dstBuf[dstOff + 1] = ((px >>  5) & 0x1F) << 3;
        dstBuf[dstOff + 2] =  (px        & 0x1F) << 3;
      }
      dstBuf[dstOff + 3] = 255;
    }
  };

  let col = 0;
  const flushRow = () => {
    if (dstRow >= 0 && dstRow < h) row.copy(rgba, dstRow * w * 4, 0, w * 4);
    dstRow--;
    col = 0;
  };

  const pxBuf = Buffer.alloc(4);
  const prevPx = Buffer.alloc(4);
  let prevSet = false;

  while (src < data.length) {
    const code = data[src++];
    const type = (code >> 4) & 0x0f;
    let   run  =  code & 0x0f;

    // Decode run length
    let n = 0;
    if (run === 0x0f) {
      // mega run: next byte = additional run count
      if (src < data.length) n = data[src++];
      run = n === 0 ? 0x10 : n + 15;
    } else if (run === 0) {
      run = 8;
    }

    switch (type) {
      case 0x00: { // REGULAR_BG_RUN
        for (let i = 0; i < run; i++) {
          // use "background pixel" (0 or XOR with prev)
          row.fill(0, col * 4, col * 4 + 4);
          if (++col >= w) flushRow();
        }
        break;
      }
      case 0x01: { // REGULAR_FG_RUN
        if (src + Bpp > data.length) break;
        data.copy(pxBuf, 0, src, src + Bpp); src += Bpp;
        for (let i = 0; i < run; i++) {
          writePixel(pxBuf, 0, row, col * 4);
          if (++col >= w) flushRow();
        }
        break;
      }
      case 0x02: { // REGULAR_FG_BG_IMAGE
        // alternating fg and bg pixels
        const fg = Buffer.alloc(Bpp);
        if (src + Bpp > data.length) break;
        data.copy(fg, 0, src, src + Bpp); src += Bpp;
        for (let i = 0; i < run; i++) {
          if (src >= data.length) break;
          const mask = data[src++];
          for (let bit = 7; bit >= 0 && i < run; bit--, i++) {
            if (mask & (1 << bit)) writePixel(fg, 0, row, col * 4);
            else row.fill(0, col * 4, col * 4 + 4);
            if (++col >= w) flushRow();
          }
          i--; // outer loop will increment
        }
        break;
      }
      case 0x03: { // REGULAR_COLOR_RUN
        if (src + Bpp > data.length) break;
        data.copy(pxBuf, 0, src, src + Bpp); src += Bpp;
        for (let i = 0; i < run; i++) {
          writePixel(pxBuf, 0, row, col * 4);
          if (++col >= w) flushRow();
        }
        break;
      }
      case 0x04: { // REGULAR_COLOR_IMAGE (uncompressed run)
        for (let i = 0; i < run; i++) {
          if (src + Bpp > data.length) break;
          data.copy(pxBuf, 0, src, src + Bpp); src += Bpp;
          writePixel(pxBuf, 0, row, col * 4);
          if (++col >= w) flushRow();
        }
        break;
      }
      default: {
        // Unknown code — best effort: skip one pixel
        if (src + Bpp <= data.length) src += Bpp;
        break;
      }
    }
  }

  return rgba;
}
