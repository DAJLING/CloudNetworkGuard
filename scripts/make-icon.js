const fs = require('fs');
const path = require('path');

const size = 256;
const pixelBytes = size * size * 4;
const maskStride = Math.ceil(size / 32) * 4;
const maskBytes = maskStride * size;
const dibSize = 40 + pixelBytes + maskBytes;
const icoSize = 6 + 16 + dibSize;
const buffer = Buffer.alloc(icoSize);

let offset = 0;
buffer.writeUInt16LE(0, offset);
offset += 2;
buffer.writeUInt16LE(1, offset);
offset += 2;
buffer.writeUInt16LE(1, offset);
offset += 2;

buffer.writeUInt8(0, offset++);
buffer.writeUInt8(0, offset++);
buffer.writeUInt8(0, offset++);
buffer.writeUInt8(0, offset++);
buffer.writeUInt16LE(1, offset);
offset += 2;
buffer.writeUInt16LE(32, offset);
offset += 2;
buffer.writeUInt32LE(dibSize, offset);
offset += 4;
buffer.writeUInt32LE(22, offset);
offset += 4;

buffer.writeUInt32LE(40, offset);
offset += 4;
buffer.writeInt32LE(size, offset);
offset += 4;
buffer.writeInt32LE(size * 2, offset);
offset += 4;
buffer.writeUInt16LE(1, offset);
offset += 2;
buffer.writeUInt16LE(32, offset);
offset += 2;
buffer.writeUInt32LE(0, offset);
offset += 4;
buffer.writeUInt32LE(pixelBytes, offset);
offset += 4;
buffer.writeInt32LE(0, offset);
offset += 4;
buffer.writeInt32LE(0, offset);
offset += 4;
buffer.writeUInt32LE(0, offset);
offset += 4;
buffer.writeUInt32LE(0, offset);
offset += 4;

for (let y = size - 1; y >= 0; y -= 1) {
  for (let x = 0; x < size; x += 1) {
    const cx = x - size / 2 + 0.5;
    const cy = y - size / 2 + 0.5;
    const distance = Math.sqrt(cx * cx + cy * cy);
    const inside = distance < 112;
    const accent = x > 128 && y > 72 && y < 184;
    const r = inside ? (accent ? 23 : 29) : 0;
    const g = inside ? (accent ? 92 : 41) : 0;
    const b = inside ? (accent ? 211 : 57) : 0;
    const a = inside ? 255 : 0;
    buffer.writeUInt8(b, offset++);
    buffer.writeUInt8(g, offset++);
    buffer.writeUInt8(r, offset++);
    buffer.writeUInt8(a, offset++);
  }
}

const outputDir = path.join(__dirname, '..', 'assets');
fs.mkdirSync(outputDir, { recursive: true });
fs.writeFileSync(path.join(outputDir, 'icon.ico'), buffer);
