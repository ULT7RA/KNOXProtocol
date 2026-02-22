import esbuild from 'esbuild';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

await esbuild.build({
  entryPoints: [path.join(root, 'renderer', 'src', 'main.jsx')],
  bundle: true,
  outfile: path.join(root, 'renderer', 'bundle.js'),
  format: 'iife',
  platform: 'browser',
  target: ['chrome118'],
  sourcemap: false,
  jsx: 'automatic',
  legalComments: 'none',
  minify: false,
  logLevel: 'info',
  loader: {
    '.png': 'file',
    '.jpg': 'file',
    '.jpeg': 'file',
    '.svg': 'file',
    '.woff2': 'file'
  }
});
