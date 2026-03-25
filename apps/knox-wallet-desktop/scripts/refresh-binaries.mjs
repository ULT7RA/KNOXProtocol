import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { spawnSync } from 'child_process';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const appRoot = path.resolve(__dirname, '..');
const repoRoot = path.resolve(appRoot, '..', '..');
const outDir = path.join(appRoot, 'bin');
const exeExt = process.platform === 'win32' ? '.exe' : '';
const defaultCargoTargetDir = path.join(repoRoot, 'target');
const cargoTargetDir = (() => {
  const raw = String(process.env.CARGO_TARGET_DIR || '').trim();
  if (!raw) return defaultCargoTargetDir;
  return path.isAbsolute(raw) ? raw : path.resolve(repoRoot, raw);
})();
const rustTarget = String(process.env.KNOX_RUST_TARGET || '').trim();
const staleBuildDirs = [
  path.join(appRoot, 'dist'),
  path.join(appRoot, 'out'),
  path.join(appRoot, 'win-unpacked')
];

const targets = [
  { pkg: 'knox-node', bin: 'knox-node', outName: `knox-node${exeExt}` },
  { pkg: 'knox-walletd', bin: 'knox-wallet', outName: `knox-wallet${exeExt}` },
  { pkg: 'knox-wallet', bin: 'knox-wallet-cli', outName: `knox-wallet-cli${exeExt}` }
];

function run(cmd, args, cwd) {
  const res = spawnSync(cmd, args, { cwd, stdio: 'inherit' });
  if (res.status !== 0) {
    throw new Error(`${cmd} ${args.join(' ')} failed with exit code ${res.status}`);
  }
}

function cargoBuildArgs(t) {
  const args = [
    'build',
    '-p', t.pkg,
    '--bin', t.bin,
    '--profile', 'release-lite',
    '--target-dir', cargoTargetDir
  ];
  if (rustTarget) {
    args.push('--target', rustTarget);
  }
  return args;
}

function resolveBuiltBinary(binName) {
  if (rustTarget) {
    const targetedCandidates = [
      path.join(cargoTargetDir, rustTarget, 'release-lite', `${binName}${exeExt}`),
      path.join(cargoTargetDir, rustTarget, 'release', `${binName}${exeExt}`)
    ];
    for (const c of targetedCandidates) {
      if (fs.existsSync(c)) return c;
    }
    throw new Error(
      `expected target-specific binary for ${binName} not found; looked in ${targetedCandidates.join(', ')}`
    );
  }

  const candidates = [
    path.join(cargoTargetDir, 'release-lite', `${binName}${exeExt}`),
    path.join(cargoTargetDir, 'release', `${binName}${exeExt}`),
    path.join(repoRoot, 'target', 'release-lite', `${binName}${exeExt}`),
    path.join(repoRoot, 'target', 'release', `${binName}${exeExt}`)
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return c;
  }
  throw new Error(`built binary not found for ${binName}; looked in ${candidates.join(', ')}`);
}

function purgeStaleOutputs() {
  console.log('[binaries] purging stale desktop artifacts...');
  for (const dir of staleBuildDirs) {
    if (fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
      console.log(`[binaries] removed ${path.relative(repoRoot, dir)}`);
    }
  }

  fs.mkdirSync(outDir, { recursive: true });
  for (const name of fs.readdirSync(outDir)) {
    const full = path.join(outDir, name);
    const st = fs.statSync(full);
    if (!st.isFile()) continue;
    // Keep only non-binary assets (for example certs in subdirectories).
    if (/\.(exe|dll|pdb)$/i.test(name)) {
      fs.rmSync(full, { force: true });
      console.log(`[binaries] removed stale ${path.relative(repoRoot, full)}`);
    }
  }
}

purgeStaleOutputs();

console.log('[binaries] building desktop runtime binaries...');
console.log(`[binaries] cargo target dir: ${cargoTargetDir}`);
if (rustTarget) {
  console.log(`[binaries] rust target triple: ${rustTarget}`);
}
for (const t of targets) {
  run('cargo', cargoBuildArgs(t), repoRoot);
}

console.log('[binaries] refreshing apps/knox-wallet-desktop/bin ...');
for (const t of targets) {
  const src = resolveBuiltBinary(t.bin);
  const dst = path.join(outDir, t.outName);
  fs.copyFileSync(src, dst);
  const stat = fs.statSync(dst);
  console.log(`[binaries] ${t.outName} <= ${src} (${stat.size} bytes)`);
}

console.log('[binaries] done');
