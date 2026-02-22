import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const appRoot = path.resolve(__dirname, '..');
const assetsDir = path.join(appRoot, 'assets');
const buildDir = path.join(appRoot, 'build');
const iconOut = path.join(buildDir, 'icon.ico');
const iconPngOut = path.join(buildDir, 'icon.png');
const nsisIconTargets = [
  path.join(buildDir, 'installerIcon.ico'),
  path.join(buildDir, 'uninstallerIcon.ico'),
  path.join(buildDir, 'installerHeaderIcon.ico')
];

function findSourcePng() {
  const candidates = [
    path.join(assetsDir, 'icon-source.png'),
    path.join(assetsDir, 'icon.png'),
    path.join(assetsDir, 'knoc.png')
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) || null;
}

function tryMagick(sourcePath, targetPath) {
  const res = spawnSync(
    'magick',
    [
      'convert',
      sourcePath,
      '-background',
      'none',
      '-define',
      'icon:auto-resize=256,128,64,48,32,24,16',
      targetPath
    ],
    { stdio: 'inherit' }
  );
  return res.status === 0;
}

function tryPowerShell(sourcePath, targetPath) {
  const script = String.raw`
param([string]$sourcePath, [string]$targetPath)
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Drawing
$sizes = @(16, 24, 32, 48, 64, 128, 256)
$sourceImage = [System.Drawing.Image]::FromFile($sourcePath)
try {
  $images = New-Object System.Collections.ArrayList
  foreach ($size in $sizes) {
    $canvas = New-Object System.Drawing.Bitmap($size, $size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    try {
      $gfx = [System.Drawing.Graphics]::FromImage($canvas)
      try {
        $gfx.Clear([System.Drawing.Color]::Transparent)
        $gfx.CompositingQuality = [System.Drawing.Drawing2D.CompositingQuality]::HighQuality
        $gfx.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $gfx.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
        $gfx.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $gfx.DrawImage($sourceImage, 0, 0, $size, $size)
      } finally {
        $gfx.Dispose()
      }

      $pngStream = New-Object System.IO.MemoryStream
      try {
        $canvas.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
        [void]$images.Add([PSCustomObject]@{ Size = $size; Bytes = $pngStream.ToArray() })
      } finally {
        $pngStream.Dispose()
      }
    } finally {
      $canvas.Dispose()
    }
  }

  $destDir = Split-Path -Parent $targetPath
  New-Item -ItemType Directory -Force -Path $destDir | Out-Null

  $fileStream = [System.IO.File]::Open($targetPath, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write)
  try {
    $writer = New-Object System.IO.BinaryWriter($fileStream)
    try {
      $writer.Write([UInt16]0)
      $writer.Write([UInt16]1)
      $writer.Write([UInt16]$images.Count)

      $offset = 6 + (16 * $images.Count)
      foreach ($img in $images) {
        $sizeByte = if ($img.Size -ge 256) { [byte]0 } else { [byte]$img.Size }
        $writer.Write($sizeByte)
        $writer.Write($sizeByte)
        $writer.Write([byte]0)
        $writer.Write([byte]0)
        $writer.Write([UInt16]1)
        $writer.Write([UInt16]32)
        $writer.Write([UInt32]$img.Bytes.Length)
        $writer.Write([UInt32]$offset)
        $offset += $img.Bytes.Length
      }

      foreach ($img in $images) {
        $writer.Write($img.Bytes)
      }
    } finally {
      $writer.Dispose()
    }
  } finally {
    $fileStream.Dispose()
  }
} finally {
  $sourceImage.Dispose()
}
`;

  const tmpPath = path.join(os.tmpdir(), `knox-icon-${Date.now()}.ps1`);
  fs.writeFileSync(tmpPath, script, 'utf8');
  try {
    const res = spawnSync(
      'powershell.exe',
      ['-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', tmpPath, sourcePath, targetPath],
      { stdio: 'inherit' }
    );
    return res.status === 0;
  } catch {
    return false;
  } finally {
    try {
      fs.unlinkSync(tmpPath);
    } catch {}
  }
}

function writePngWrappedIco(sourcePath, targetPath) {
  const png = fs.readFileSync(sourcePath);
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  if (png.length < 24 || !png.subarray(0, 8).equals(signature)) {
    throw new Error(`source is not a valid PNG: ${sourcePath}`);
  }

  const width = png.readUInt32BE(16);
  const height = png.readUInt32BE(20);
  const widthByte = width >= 256 ? 0 : width;
  const heightByte = height >= 256 ? 0 : height;

  const header = Buffer.alloc(22);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(1, 4);
  header.writeUInt8(widthByte, 6);
  header.writeUInt8(heightByte, 7);
  header.writeUInt8(0, 8);
  header.writeUInt8(0, 9);
  header.writeUInt16LE(1, 10);
  header.writeUInt16LE(32, 12);
  header.writeUInt32LE(png.length, 14);
  header.writeUInt32LE(22, 18);

  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.writeFileSync(targetPath, Buffer.concat([header, png]));
}

function syncNsisIconFiles(sourceIcoPath) {
  for (const target of nsisIconTargets) {
    try {
      fs.copyFileSync(sourceIcoPath, target);
    } catch (err) {
      console.warn(`[icon] warning: could not write ${path.relative(appRoot, target)}: ${String(err.message || err)}`);
    }
  }
}

const sourcePng = findSourcePng();
if (!sourcePng) {
  throw new Error(
    'No source icon PNG found. Add one of: assets/icon-source.png, assets/icon.png, assets/knoc.png'
  );
}

console.log(`[icon] source: ${path.relative(appRoot, sourcePng)}`);
console.log(`[icon] target: ${path.relative(appRoot, iconOut)}`);

fs.mkdirSync(buildDir, { recursive: true });
try {
  fs.copyFileSync(sourcePng, iconPngOut);
} catch (err) {
  console.warn(`[icon] warning: could not write ${path.relative(appRoot, iconPngOut)}: ${String(err.message || err)}`);
}

if (tryMagick(sourcePng, iconOut)) {
  console.log('[icon] generated via ImageMagick');
  syncNsisIconFiles(iconOut);
  process.exit(0);
}

if (process.platform === 'win32' && tryPowerShell(sourcePng, iconOut)) {
  console.log('[icon] generated via PowerShell/System.Drawing');
  syncNsisIconFiles(iconOut);
  process.exit(0);
}

if (process.platform === 'win32') {
  throw new Error(
    'Failed to generate build/icon.ico on Windows. Install ImageMagick (`magick`) or ensure PowerShell + System.Drawing are available.'
  );
}

writePngWrappedIco(sourcePng, iconOut);
console.log('[icon] generated via PNG wrapper fallback');
syncNsisIconFiles(iconOut);
