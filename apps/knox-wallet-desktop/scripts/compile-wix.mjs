import { spawnSync } from 'child_process';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

const wixDir = 'C:\\Users\\lamou\\AppData\\Local\\electron-builder\\Cache\\wix\\wix-4.0.0.5512.2';
const candle  = path.join(wixDir, 'candle.exe');
const wixUtil = path.join(wixDir, 'WixUtilExtension.dll');

const result = spawnSync(candle, [
  '-arch', 'x64',
  '-ext',  wixUtil,
  path.join(root, 'build', 'wix-extras.wxs'),
  '-out',  path.join(root, 'build', 'wix-extras.wixobj')
], { stdio: 'inherit', shell: false });

process.exit(result.status ?? 1);
