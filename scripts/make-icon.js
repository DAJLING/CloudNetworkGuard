const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const outputDir = path.join(__dirname, '..', 'assets');
const defaultSource = path.join(outputDir, 'app-icon.png');
const sourceIcon = path.resolve(process.argv[2] || defaultSource);

const iconSizes = [16, 32, 48, 64, 128, 256, 512, 1024];
const icoSizes = [16, 32, 48, 64, 128, 256];
const icnsTypes = new Map([
  [16, 'icp4'],
  [32, 'icp5'],
  [64, 'icp6'],
  [128, 'ic07'],
  [256, 'ic08'],
  [512, 'ic09'],
  [1024, 'ic10']
]);

function writeUInt32BE(buffer, value, offset) {
  buffer.writeUInt32BE(value, offset);
}

function writeIco(entries, outputPath) {
  const headerSize = 6;
  const directorySize = entries.length * 16;
  const totalSize = headerSize + directorySize + entries.reduce((sum, entry) => sum + entry.data.length, 0);
  const buffer = Buffer.alloc(totalSize);
  let offset = 0;

  buffer.writeUInt16LE(0, offset);
  offset += 2;
  buffer.writeUInt16LE(1, offset);
  offset += 2;
  buffer.writeUInt16LE(entries.length, offset);
  offset += 2;

  let imageOffset = headerSize + directorySize;
  for (const entry of entries) {
    buffer.writeUInt8(entry.size >= 256 ? 0 : entry.size, offset++);
    buffer.writeUInt8(entry.size >= 256 ? 0 : entry.size, offset++);
    buffer.writeUInt8(0, offset++);
    buffer.writeUInt8(0, offset++);
    buffer.writeUInt16LE(1, offset);
    offset += 2;
    buffer.writeUInt16LE(32, offset);
    offset += 2;
    buffer.writeUInt32LE(entry.data.length, offset);
    offset += 4;
    buffer.writeUInt32LE(imageOffset, offset);
    offset += 4;
    imageOffset += entry.data.length;
  }

  for (const entry of entries) {
    entry.data.copy(buffer, offset);
    offset += entry.data.length;
  }

  fs.writeFileSync(outputPath, buffer);
}

function writeIcns(entries, outputPath) {
  const chunks = entries.map((entry) => {
    const type = icnsTypes.get(entry.size);
    const chunk = Buffer.alloc(8 + entry.data.length);
    chunk.write(type, 0, 4, 'ascii');
    writeUInt32BE(chunk, chunk.length, 4);
    entry.data.copy(chunk, 8);
    return chunk;
  });

  const totalSize = 8 + chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const header = Buffer.alloc(8);
  header.write('icns', 0, 4, 'ascii');
  writeUInt32BE(header, totalSize, 4);
  fs.writeFileSync(outputPath, Buffer.concat([header, ...chunks], totalSize));
}

function resizeWithPowerShell(sourcePath, tempDir) {
  const scriptPath = path.join(tempDir, 'resize-icons.ps1');
  const psScript = `
param(
  [Parameter(Mandatory=$true)][string]$Source,
  [Parameter(Mandatory=$true)][string]$OutputDir,
  [Parameter(Mandatory=$true)][string]$SizesCsv
)
Add-Type -AssemblyName System.Drawing
$sizes = $SizesCsv.Split(',') | ForEach-Object { [int]$_ }
$sourceImage = [System.Drawing.Image]::FromFile($Source)
try {
  foreach ($size in $sizes) {
    $bitmap = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
      $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
      try {
        $graphics.Clear([System.Drawing.Color]::Transparent)
        $graphics.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $graphics.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $scale = [Math]::Min($size / $sourceImage.Width, $size / $sourceImage.Height)
        $drawWidth = [int][Math]::Round($sourceImage.Width * $scale)
        $drawHeight = [int][Math]::Round($sourceImage.Height * $scale)
        $x = [int][Math]::Floor(($size - $drawWidth) / 2)
        $y = [int][Math]::Floor(($size - $drawHeight) / 2)
        $graphics.DrawImage($sourceImage, $x, $y, $drawWidth, $drawHeight)
      } finally {
        $graphics.Dispose()
      }
      $bitmap.Save((Join-Path $OutputDir "$size.png"), [System.Drawing.Imaging.ImageFormat]::Png)
    } finally {
      $bitmap.Dispose()
    }
  }
} finally {
  $sourceImage.Dispose()
}
`;
  fs.writeFileSync(scriptPath, psScript.trimStart(), 'utf8');

  const result = spawnSync(
    'powershell.exe',
    ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', scriptPath, sourcePath, tempDir, iconSizes.join(',')],
    { encoding: 'utf8' }
  );

  if (result.status !== 0) {
    throw new Error(`Icon resize failed:\n${result.stdout}\n${result.stderr}`);
  }
}

if (!fs.existsSync(sourceIcon)) {
  throw new Error(`Source icon not found: ${sourceIcon}`);
}

fs.mkdirSync(outputDir, { recursive: true });
fs.copyFileSync(sourceIcon, defaultSource);

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'network-guard-icons-'));
try {
  resizeWithPowerShell(defaultSource, tempDir);

  const pngEntries = iconSizes.map((size) => ({
    size,
    data: fs.readFileSync(path.join(tempDir, `${size}.png`))
  }));

  writeIco(
    pngEntries.filter((entry) => icoSizes.includes(entry.size)),
    path.join(outputDir, 'icon.ico')
  );
  writeIcns(
    pngEntries.filter((entry) => icnsTypes.has(entry.size)),
    path.join(outputDir, 'icon.icns')
  );
} finally {
  fs.rmSync(tempDir, { recursive: true, force: true });
}

console.log(`Wrote ${path.join(outputDir, 'app-icon.png')}`);
console.log(`Wrote ${path.join(outputDir, 'icon.ico')}`);
console.log(`Wrote ${path.join(outputDir, 'icon.icns')}`);
