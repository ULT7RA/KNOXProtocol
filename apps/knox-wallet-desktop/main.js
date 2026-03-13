const { app, BrowserWindow, ipcMain, Menu } = require('electron');
const { spawn, execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const https = require('https');
const selfsigned = require('selfsigned');

const ROOT = __dirname;
const USER_DIR = app.getPath('userData');
const LOCAL_CACHE_BASE = process.env.LOCALAPPDATA
  || path.join(process.env.USERPROFILE || process.env.HOME || USER_DIR, 'AppData', 'Local');
const CACHE_DIR = path.join(LOCAL_CACHE_BASE, 'knox-wallet-desktop', 'Cache');
try {
  fs.mkdirSync(CACHE_DIR, { recursive: true });
  app.setPath('cache', CACHE_DIR);
} catch {
  app.disableHardwareAcceleration();
}
app.commandLine.appendSwitch('disable-gpu-shader-disk-cache');
const DATA_DIR = path.join(USER_DIR, 'data');
const CERT_DIR = path.join(USER_DIR, 'tls');
const LOG_DIR = path.join(USER_DIR, 'logs');
const HOME = process.env.USERPROFILE || process.env.HOME || USER_DIR;
const WALLET_CFG_DIR = path.join(HOME, '.knox', 'wallet');
const MAIN_LOG_PATH = path.join(LOG_DIR, 'main.log');
const WALLET_PATH = path.join(USER_DIR, 'knox-wallet.bin');
const WALLET_BACKUP_DIR = path.join(USER_DIR, 'wallet-backups');
const NODE_DATA_DIR = path.join(DATA_DIR, 'node');
const NODE_KEY_PATH = path.join(NODE_DATA_DIR, 'node.key');
const NODE_LEDGER_DIR = path.join(NODE_DATA_DIR, 'ledger');
const LEDGER_VERSION_MARKER_PATH = path.join(NODE_DATA_DIR, '.ledger-version');
const MINING_CFG_PATH = path.join(WALLET_CFG_DIR, 'mining.toml');
const CERT_PATH = path.join(CERT_DIR, 'walletd.crt');
const KEY_PATH = path.join(CERT_DIR, 'walletd.key');
// Packaged desktop must always run in mainnet-lock mode regardless of shell env.
const MAINNET_LOCKED = app.isPackaged || /^(1|true|yes)$/i.test(
  String(process.env.KNOX_MAINNET_LOCK || '0')
);
// Safety default: never rewrite an existing wallet file because of transient
// CLI parse failures. This can be re-enabled explicitly for emergency recovery.
const AUTO_IMPORT_ON_ADDRESS_PARSE_FAILURE = /^(1|true|yes)$/i.test(
  String(process.env.KNOX_AUTO_IMPORT_ON_ADDRESS_PARSE_FAILURE || '0')
);
const NETWORK_ENV_OVERRIDE_REQUESTED = /^(1|true|yes)$/i.test(
  String(process.env.KNOX_DESKTOP_ALLOW_NETWORK_ENV_OVERRIDE || '0')
);
// Safety default: packaged builds must not let shell env pin P2P/RPC to a
// stale endpoint. Keep override support for local/dev runs only.
const ALLOW_NETWORK_ENV_OVERRIDES = !app.isPackaged && !MAINNET_LOCKED && NETWORK_ENV_OVERRIDE_REQUESTED;

const DEFAULT_PUBLIC_P2P_SEEDS = String(process.env.KNOX_DEFAULT_PUBLIC_P2P_SEEDS || '')
  .split(/[,\s]+/)
  .map((s) => s.trim())
  .filter(Boolean);
const DEFAULT_RPC_FALLBACK = normalizeRpcEndpoint(
  process.env.KNOX_DEFAULT_PUBLIC_RPC || '',
  '127.0.0.1:9736'
);

function splitRpcEndpoint(ep) {
  const m = String(ep || '').match(/^(.+):(\d{2,5})$/);
  if (!m) return null;
  const port = Number(m[2]);
  if (!Number.isFinite(port) || port < 1 || port > 65535) return null;
  return { host: m[1], port };
}

function normalizeRpcEndpoint(raw, fallback = DEFAULT_RPC_FALLBACK) {
  const src = String(raw || '').trim().replace(/^["']+|["']+$/g, '');
  const candidates = src
    .split(/[,\s]+/)
    .map((s) => s.trim().replace(/^["']+|["']+$/g, ''))
    .filter(Boolean);
  for (const c of candidates) {
    const parts = splitRpcEndpoint(c);
    if (parts) return `${parts.host}:${parts.port}`;
  }
  return fallback;
}

const DEFAULT_PUBLIC_RPC_CANDIDATES = (() => {
  const raw = String(
    process.env.KNOX_DEFAULT_PUBLIC_RPC_CANDIDATES
      || process.env.KNOX_DEFAULT_PUBLIC_RPC
      || ''
  )
    .split(/[,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  return raw.length ? raw : [DEFAULT_RPC_FALLBACK];
})();
const DEFAULT_MAINNET_GENESIS_HASH = 'd626848546f6511abd38a1ee89610a708d001d53e0c8a27dc509a1e65b964187';
const DESKTOP_APP_VERSION = '1.3.16';
const MIN_SUPPORTED_INSTALLER_VERSION =
  '1.3.16';
const MIN_SUPPORTED_P2P_PROTOCOL_VERSION = 2;
const RPC_UPSTREAM = normalizeRpcEndpoint(
  ALLOW_NETWORK_ENV_OVERRIDES ? process.env.KNOX_PUBLIC_RPC_ADDR : '',
  DEFAULT_PUBLIC_RPC_CANDIDATES[0]
);
const P2P_UPSTREAM = normalizePeerList(
  (ALLOW_NETWORK_ENV_OVERRIDES ? process.env.KNOX_PUBLIC_P2P_ADDR : '')
    || DEFAULT_PUBLIC_P2P_SEEDS.join(',')
);

function normalizePeerList(raw) {
  const entries = String(raw || '')
    .split(/[,\s]+/)
    .map((s) => s.trim().replace(/^["']+|["']+$/g, ''))
    .filter(Boolean);
  if (!entries.length) return '';
  const byHost = new Map();
  for (const ep of entries) {
    const parts = splitRpcEndpoint(ep);
    if (!parts) continue;
    const key = parts.host;
    const current = byHost.get(key);
    if (!current) {
      byHost.set(key, parts);
      continue;
    }
    // Prefer canonical lane (:9735). Keep prior choice if already canonical.
    if (current.port === 9735) continue;
    if (parts.port === 9735) {
      byHost.set(key, parts);
      continue;
    }
    // Otherwise prefer primary lane over secondary lane.
    if (current.port === 9745 && parts.port !== 9745) {
      byHost.set(key, parts);
    }
  }
  return Array.from(byHost.values())
    .map((p) => `${p.host}:${p.port}`)
    .join(',');
}

function rpcCandidateList() {
  const out = [];
  const seen = new Set();
  const push = (ep) => {
    const n = normalizeRpcEndpoint(ep, '');
    if (!n || seen.has(n)) return;
    seen.add(n);
    out.push(n);
  };

  // Seed from stable defaults first so a stale env override cannot pin us to one flaky node.
  for (const ep of DEFAULT_PUBLIC_RPC_CANDIDATES) push(ep);

  // Primary explicit endpoint still gets included.
  const envPrimary = normalizeRpcEndpoint(
    ALLOW_NETWORK_ENV_OVERRIDES ? (process.env.KNOX_PUBLIC_RPC_ADDR || RPC_UPSTREAM) : RPC_UPSTREAM,
    ''
  );
  push(envPrimary);

  // Allow comma-separated overrides in env.
  if (ALLOW_NETWORK_ENV_OVERRIDES) {
    String(process.env.KNOX_PUBLIC_RPC_ADDR || '')
      .split(/[,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean)
      .forEach((ep) => push(normalizeRpcEndpoint(ep, '')));
  }
  // For packaged/mainnet builds, do not infer RPC endpoints from peer hosts.
  // Some peers are intentionally P2P-only and will flap walletd probes.
  if (ALLOW_NETWORK_ENV_OVERRIDES) {
    const hosts = new Set();
    String(P2P_UPSTREAM || '')
      .split(/[,\s]+/)
      .map((s) => s.trim().replace(/^["']+|["']+$/g, ''))
      .filter(Boolean)
      .forEach((ep) => {
        const m = ep.match(/^(.+):(\d{2,5})$/);
        if (m) hosts.add(m[1]);
      });
    for (const h of hosts) {
      push(`${h}:9736`);
    }
  }
  if (!out.length) out.push(DEFAULT_PUBLIC_RPC_CANDIDATES[0]);
  return out;
}
const WALLETD_BIND = process.env.KNOX_WALLETD_BIND || '127.0.0.1:9980';
const LOCAL_NODE_P2P = process.env.KNOX_LOCAL_NODE_P2P || '0.0.0.0:19735';
const LOCAL_NODE_RPC = process.env.KNOX_LOCAL_NODE_RPC || '127.0.0.1:19736';
// Launch policy: walletd must stay on upstream RPC so GUI always tracks network chain (never local-only tip).
// Keep this hard-locked off for production launch behavior.
const USE_LOCAL_RPC_WHEN_NODE_RUNNING = false;
const USE_VALIDATORS_FILE_FOR_DESKTOP_NODE = /^(1|true|yes)$/i.test(String(process.env.KNOX_DESKTOP_USE_VALIDATORS_FILE || '1'));
const DESKTOP_INSECURE_DEV = !app.isPackaged
  && /^(1|true|yes)$/i.test(String(process.env.KNOX_DESKTOP_INSECURE_DEV || '0'));
const CONSENSUS_SAFE_ENV_KEYS = [
  'KNOX_ALLOW_UNSAFE_OVERRIDES',
  'KNOX_LATTICE_MINING_DEBUG',
  'KNOX_LATTICE_DEBUG_DIFFICULTY_BITS',
  'KNOX_LATTICE_DEBUG_SEQ_STEPS',
  'KNOX_LATTICE_DEBUG_MEMORY_BYTES',
  'KNOX_DESKTOP_LOCAL_ALLOW_UNVERIFIED',
];
const DESKTOP_UPSTREAM_SYNC_BATCH = 64;
const DESKTOP_UPSTREAM_SYNC_TIMEOUT_MS = 120000;
const MAINNET_LOCK_STRIP_ENV_KEYS = [
  'KNOX_NODE_MINING_MODE',
  'KNOX_NODE_MINING_BACKEND',
  'KNOX_NODE_MINING_DIFFICULTY_BITS',
  'KNOX_NODE_MINING_SEQ_STEPS',
  'KNOX_NODE_MINING_MEMORY_BYTES',
  'KNOX_NODE_MINING_CPU_UTIL',
  'KNOX_NODE_MINING_GPU_UTIL',
  'KNOX_NODE_GPU_DEVICE_ID',
  'KNOX_NODE_CUDA_DEVICE_ORDINAL',
  'KNOX_LATTICE_OPEN_MINING',
  'KNOX_NODE_SKIP_VALIDATORS',
  'KNOX_P2P_ALLOW_PLAINTEXT',
  'KNOX_P2P_PSK',
  'KNOX_DISABLE_MAINNET_ENV_LOCK',
  'KNOX_VELOX_DAG_NODES',
  'KNOX_NODE_UPSTREAM_SYNC_BATCH_COUNT',
  'KNOX_NODE_UPSTREAM_SYNC_TIMEOUT_MS',
  'KNOX_UPSTREAM_PROBE_TIMEOUT_MS',
  'KNOX_WALLETD_NETWORK_TIMEOUT_MS',
  'KNOX_UPSTREAM_RPC_CONNECT_TIMEOUT_MS',
  'KNOX_UPSTREAM_RPC_IO_TIMEOUT_MS',
];
// Emergency override for remote-only wallet mode (disables local node start path).
const FORCE_REMOTE_WALLET_MODE = /^(1|true|yes)$/i.test(String(process.env.KNOX_DESKTOP_FORCE_REMOTE_ONLY || '0'));
// If upstream probes are flaky, allow node startup and let P2P catch up instead of hard-failing UX.
const ALLOW_DEGRADED_UPSTREAM_BOOT = !/^(0|false|no)$/i.test(
  String(process.env.KNOX_ALLOW_DEGRADED_UPSTREAM_BOOT || '1')
);
const UPSTREAM_PROBE_TIMEOUT_MS = Math.max(
  3000,
  Number.parseInt(String(process.env.KNOX_UPSTREAM_PROBE_TIMEOUT_MS || '30000'), 10) || 30000
);
const UPSTREAM_PROBE_ATTEMPTS = Math.max(
  1,
  Math.min(5, Number.parseInt(String(process.env.KNOX_UPSTREAM_PROBE_ATTEMPTS || '3'), 10) || 3)
);
const UPSTREAM_FAILOVER_STREAK = Math.max(
  1,
  Math.min(6, Number.parseInt(String(process.env.KNOX_UPSTREAM_FAILOVER_STREAK || '3'), 10) || 3)
);
const WALLETD_NETWORK_TIMEOUT_MS = Math.max(
  10000,
  Number.parseInt(String(process.env.KNOX_WALLETD_NETWORK_TIMEOUT_MS || '120000'), 10) || 120000
);
const UPSTREAM_RPC_CONNECT_TIMEOUT_MS = Math.max(
  2000,
  Number.parseInt(String(process.env.KNOX_UPSTREAM_RPC_CONNECT_TIMEOUT_MS || '15000'), 10) || 15000
);
const UPSTREAM_RPC_IO_TIMEOUT_MS = Math.max(
  5000,
  Number.parseInt(String(process.env.KNOX_UPSTREAM_RPC_IO_TIMEOUT_MS || '120000'), 10) || 120000
);
const WALLETD_FAILOVER_COOLDOWN_MS = Math.max(
  5000,
  Number.parseInt(String(process.env.KNOX_WALLETD_FAILOVER_COOLDOWN_MS || '60000'), 10) || 60000
);
const WALLETD_RUNTIME_FAILOVER_ENABLED = /^(1|true|yes)$/i.test(
  String(process.env.KNOX_WALLETD_RUNTIME_FAILOVER || (MAINNET_LOCKED ? '1' : '0'))
);
const UPSTREAM_MINING_SAFETY_STREAK = Math.max(
  3,
  Math.min(20, Number.parseInt(String(process.env.KNOX_UPSTREAM_MINING_SAFETY_STREAK || '8'), 10) || 8)
);
const UPSTREAM_MINING_SAFETY_GRACE_MS = Math.max(
  30000,
  Number.parseInt(String(process.env.KNOX_UPSTREAM_MINING_SAFETY_GRACE_MS || '120000'), 10) || 120000
);
const UPSTREAM_MINING_SAFETY_AUTO_OFF = /^(1|true|yes)$/i.test(
  String(process.env.KNOX_UPSTREAM_MINING_SAFETY_AUTO_OFF || '0')
);
const AUTOSTART_ON_OPEN = !/^(0|false|no)$/i.test(String(process.env.KNOX_DESKTOP_AUTOSTART || '1'));
const AUTO_LEDGER_RESET_ENABLED = !/^(0|false|no)$/i.test(String(process.env.KNOX_DESKTOP_AUTO_LEDGER_RESET || '1'));
const PURGE_LEDGER_ON_APP_UPDATE = !/^(0|false|no)$/i.test(String(process.env.KNOX_PURGE_LEDGER_ON_UPDATE || '1'));
const TOKEN = process.env.KNOX_WALLETD_TOKEN || crypto.randomBytes(24).toString('hex');

function safeShortAddress(addr) {
  if (!addr || typeof addr !== 'string') return '(unknown)';
  if (addr.length <= 16) return addr;
  return addr.slice(0, 8) + '…' + addr.slice(-8);
}

const service = {
  node: null,
  walletd: null,
};
const lastExit = {
  node: null,
  walletd: null,
};
const runtimeStats = {
  node: {
    running: false,
    lastProposeHeight: null,
    lastProposeRound: null,
    lastProposeAtMs: 0,
    lastReject: '',
    lastSealedHeight: null,
    lastSealedAtMs: 0,
    sealedCount: 0,
    currentDifficultyBits: 0,
    totalHardeningEstimate: 0,
    currentStreak: 0,
    miningMode: 'hybrid',
    configuredBackend: 'auto',
    activeBackend: 'cpu',
    availableBackends: ['cpu'],
    activeDevice: 'cpu-main',
    minerAddress: '',
    fallbackActive: false,
    lastBackendError: '',
    recentBlocks: [],
    pendingRewardEvents: []
  },
  walletd: {
    running: false,
    listening: false,
    lastSyncError: '',
    lastInfoError: '',
    lastInfoAtMs: 0
  }
};
let mainWindow = null;
let quickStartBusy = false;
let walletdRpcTarget = null;
let nodeMineEnabled = true;
let miningProfileState = null;
let desktopMinerAddress = '';
let walletAutoSyncTimer = null;
let walletAutoSyncInFlight = false;
let walletAutoSyncQueued = false;
let walletAutoSyncFailCount = 0;
let walletAutoSyncFallbackAtMs = 0;
let upstreamFailureStreak = 0;
let upstreamFailureFirstAtMs = 0;
let upstreamSafetyDisabledNoticeAtMs = 0;
let walletdFailoverCooldownUntilMs = 0;
let walletdSwitchPromise = null;
let walletdAutoRecoverPromise = null;
let miningSafetyTripped = false;
let lastUpstreamTipSeen = 0;
let lastTipRegressionLogMs = 0;
let lastGoodNetworkTelemetry = null;
const UPSTREAM_TIP_REGRESSION_TOLERANCE = Math.max(
  8,
  Number.parseInt(String(process.env.KNOX_UPSTREAM_TIP_REGRESSION_TOLERANCE || '32'), 10) || 32
);
const walletBackupAtByReason = new Map();
let autoLedgerResetInFlight = false;
let autoLedgerResetCooldownUntilMs = 0;
const autoLedgerResetState = {
  firstAtMs: 0,
  lastAtMs: 0,
  hitCount: 0
};

function resetRuntimeMiningSession() {
  runtimeStats.node.sealedCount = 0;
  runtimeStats.node.currentStreak = 0;
  runtimeStats.node.lastSealedHeight = null;
  runtimeStats.node.lastSealedAtMs = 0;
  runtimeStats.node.totalHardeningEstimate = 0;
  runtimeStats.node.recentBlocks = [];
  runtimeStats.node.pendingRewardEvents = [];
}

function resetUpstreamFailureState() {
  upstreamFailureStreak = 0;
  upstreamFailureFirstAtMs = 0;
}

const gotSingleInstanceLock = app.requestSingleInstanceLock();
if (!gotSingleInstanceLock) {
  app.quit();
}

function defaultPeerList() {
  const envPeers = normalizePeerList(
    ALLOW_NETWORK_ENV_OVERRIDES ? (process.env.KNOX_DESKTOP_LOCAL_PEERS || '') : ''
  );
  if (envPeers) return envPeers;
  return normalizePeerList(P2P_UPSTREAM);
}

function envBoolOverride(name) {
  if (!(name in process.env)) return null;
  const v = String(process.env[name] || '').trim().toLowerCase();
  if (!v) return null;
  if (v === '1' || v === 'true' || v === 'yes' || v === 'on') return true;
  if (v === '0' || v === 'false' || v === 'no' || v === 'off') return false;
  return null;
}

function detectMiningBackends() {
  const available = ['cpu'];
  const devices = [{ id: 0, backend: 'cpu', label: 'cpu-main' }];
  const windir = process.env.WINDIR || 'C:\\Windows';
  const openclOverride = envBoolOverride('KNOX_FORCE_OPENCL_AVAILABLE');
  const cudaOverride = envBoolOverride('KNOX_FORCE_CUDA_AVAILABLE');
  const openclCandidates = [
    path.join(windir, 'System32', 'OpenCL.dll'),
    path.join(windir, 'SysWOW64', 'OpenCL.dll'),
    '/usr/lib/libOpenCL.so',
    '/usr/lib/libOpenCL.so.1',
    '/usr/lib/x86_64-linux-gnu/libOpenCL.so',
    '/usr/lib/x86_64-linux-gnu/libOpenCL.so.1'
  ];
  const cudaCandidates = [
    path.join(windir, 'System32', 'nvcuda.dll'),
    path.join(windir, 'SysWOW64', 'nvcuda.dll'),
    '/usr/lib/libcuda.so',
    '/usr/lib/libcuda.so.1',
    '/usr/lib/x86_64-linux-gnu/libcuda.so',
    '/usr/lib/x86_64-linux-gnu/libcuda.so.1'
  ];
  const existsAny = (paths) => paths.some((p) => fs.existsSync(p));
  const openclAvailable = openclOverride !== null ? openclOverride : (process.platform === 'win32' ? true : existsAny(openclCandidates));
  const cudaAvailable = cudaOverride !== null ? cudaOverride : (process.platform === 'win32' ? true : existsAny(cudaCandidates));
  if (openclAvailable) {
    available.push('opencl');
    devices.push({ id: 0, backend: 'opencl', label: 'opencl-0' });
  }
  if (cudaAvailable) {
    available.push('cuda');
    devices.push({ id: 0, backend: 'cuda', label: 'cuda-0' });
  }
  return {
    availableBackends: available,
    preferredBackend: cudaAvailable ? 'cuda' : (openclAvailable ? 'opencl' : 'cpu'),
    devices
  };
}

function binCandidates(name) {
  const raw = [
    path.join(ROOT, 'bin', name),
    path.resolve(ROOT, '..', 'app.asar.unpacked', 'bin', name),
    path.join(process.resourcesPath || '', 'bin', name),
    path.join(process.resourcesPath || '', 'app.asar.unpacked', 'bin', name)
  ].filter(Boolean);
  const seen = new Set();
  return raw.filter((p) => {
    const key = String(p || '').toLowerCase();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function resolveBin(name) {
  const candidates = binCandidates(name);
  return candidates.find((p) => fs.existsSync(p)) || candidates[0];
}

function listSetupExesInDir(dirPath) {
  try {
    const names = fs.readdirSync(dirPath);
    return names
      .filter((name) => /^KNOX WALLET Setup .*\.exe$/i.test(name))
      .map((name) => {
        const fullPath = path.join(dirPath, name);
        const stat = fs.statSync(fullPath);
        return { fullPath, mtimeMs: Number(stat.mtimeMs || 0) };
      })
      .sort((a, b) => b.mtimeMs - a.mtimeMs)
      .map((entry) => entry.fullPath);
  } catch {
    return [];
  }
}

function findLatestInstallerExe() {
  const explicit = String(process.env.KNOX_INSTALLER_PATH || '').trim();
  if (explicit && fs.existsSync(explicit)) return explicit;

  const dirs = new Set([
    app.getPath('downloads'),
    path.dirname(process.execPath),
    path.resolve(path.dirname(process.execPath), '..'),
    path.resolve(path.dirname(process.execPath), '..', '..'),
    path.join(ROOT, 'dist')
  ]);

  for (const dirPath of dirs) {
    if (!dirPath) continue;
    const hits = listSetupExesInDir(dirPath);
    if (hits.length) return hits[0];
  }
  return '';
}

async function launchInstallerFromApp(win) {
  const installerPath = findLatestInstallerExe();
  if (!installerPath) {
    return {
      ok: false,
      error: 'Installer not found. Place "KNOX WALLET Setup *.exe" in Downloads or app folder, then retry.'
    };
  }

  appendLog(win, `[install] launching installer: ${installerPath}`);
  stopSvc('node');
  stopSvc('walletd');
  await waitMs(250);
  try {
    const child = spawn(installerPath, [], {
      detached: true,
      stdio: 'ignore'
    });
    child.unref();
  } catch (err) {
    return { ok: false, error: `failed to launch installer: ${String(err?.message || err)}` };
  }

  setTimeout(() => {
    try {
      app.quit();
    } catch { }
  }, 300);

  return { ok: true, result: `installer launched: ${installerPath}` };
}

function ensureDirs() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(CERT_DIR, { recursive: true });
  fs.mkdirSync(LOG_DIR, { recursive: true });
  fs.mkdirSync(NODE_DATA_DIR, { recursive: true });
  fs.mkdirSync(WALLET_CFG_DIR, { recursive: true });
  fs.mkdirSync(WALLET_BACKUP_DIR, { recursive: true });
}

function purgeLedgerOnVersionChange(win) {
  if (!PURGE_LEDGER_ON_APP_UPDATE) return { ok: true, result: 'ledger purge on update disabled' };
  ensureDirs();
  const currentVersion = String(app.getVersion() || '').trim() || '0.0.0';
  let previousVersion = '';
  try {
    previousVersion = String(fs.readFileSync(LEDGER_VERSION_MARKER_PATH, 'utf8') || '').trim();
  } catch {
    previousVersion = '';
  }
  if (previousVersion === currentVersion) {
    return { ok: true, result: `ledger marker up to date (${currentVersion})` };
  }
  try {
    if (fs.existsSync(NODE_LEDGER_DIR)) {
      fs.rmSync(NODE_LEDGER_DIR, { recursive: true, force: true });
      appendLog(win || mainWindow, `[repair] purged local ledger on app update ${previousVersion || 'none'} -> ${currentVersion}`);
    } else {
      appendLog(win || mainWindow, `[repair] no local ledger to purge on app update ${previousVersion || 'none'} -> ${currentVersion}`);
    }
  } catch (err) {
    const msg = `failed to purge local ledger on update: ${String(err?.message || err)}`;
    appendLog(win || mainWindow, `[warn] ${msg}`);
    return { ok: false, error: msg };
  }
  try {
    fs.writeFileSync(LEDGER_VERSION_MARKER_PATH, `${currentVersion}\n`, 'utf8');
  } catch (err) {
    const msg = `failed to write ledger version marker: ${String(err?.message || err)}`;
    appendLog(win || mainWindow, `[warn] ${msg}`);
    return { ok: false, error: msg };
  }
  return { ok: true, result: `ledger marker updated to ${currentVersion}` };
}

function backupWalletSnapshot(win, reason = 'manual', opts = {}) {
  try {
    if (!fs.existsSync(WALLET_PATH)) return { ok: true, result: 'wallet missing; no backup needed' };
    const sz = Number(fs.statSync(WALLET_PATH).size || 0);
    if (sz <= 0) return { ok: true, result: 'wallet empty; no backup needed' };
    const minIntervalMs = Number(opts.minIntervalMs || 0);
    const now = Date.now();
    const key = String(reason || 'manual');
    const last = Number(walletBackupAtByReason.get(key) || 0);
    if (minIntervalMs > 0 && now - last < minIntervalMs) {
      return { ok: true, result: `backup skipped (interval ${minIntervalMs}ms)` };
    }
    const stamp = new Date(now).toISOString().replace(/[:.]/g, '-');
    const safeReason = key.replace(/[^a-z0-9_-]/gi, '_').slice(0, 48) || 'manual';
    const backupPath = path.join(WALLET_BACKUP_DIR, `knox-wallet.${stamp}.${safeReason}.bin`);
    fs.copyFileSync(WALLET_PATH, backupPath);
    walletBackupAtByReason.set(key, now);
    appendLog(win || mainWindow, `[wallet] backup created: ${backupPath}`);
    return { ok: true, result: backupPath };
  } catch (err) {
    const msg = `wallet backup failed: ${String(err?.message || err)}`;
    appendLog(win || mainWindow, `[warn] ${msg}`);
    return { ok: false, error: msg };
  }
}

function listWalletBackups(limit = 50) {
  ensureDirs();
  const max = Math.max(1, Math.min(500, Number(limit) || 50));
  if (!fs.existsSync(WALLET_BACKUP_DIR)) return [];
  const names = fs.readdirSync(WALLET_BACKUP_DIR)
    .filter((n) => /^knox-wallet\..+\.bin$/i.test(n))
    .map((n) => {
      const p = path.join(WALLET_BACKUP_DIR, n);
      let st;
      try {
        st = fs.statSync(p);
      } catch {
        return null;
      }
      return {
        name: n,
        path: p,
        size: Number(st.size || 0),
        mtimeMs: Number(st.mtimeMs || 0)
      };
    })
    .filter(Boolean)
    .sort((a, b) => b.mtimeMs - a.mtimeMs);
  return names.slice(0, max);
}

async function restoreWalletBackup(win, backupPath = '') {
  try {
    const candidates = backupPath
      ? [{ path: String(backupPath).trim() }]
      : listWalletBackups(1);
    const src = String(candidates?.[0]?.path || '').trim();
    if (!src) return { ok: false, error: 'no wallet backup found' };
    if (!fs.existsSync(src)) return { ok: false, error: `backup not found: ${src}` };
    const st = fs.statSync(src);
    if (Number(st.size || 0) <= 0) return { ok: false, error: `backup is empty: ${src}` };

    const wasWalletdRunning = !!service.walletd;
    const targetRpc = walletdRpcTarget || walletdRpcAddr();
    if (wasWalletdRunning) {
      stopSvc('walletd');
      await waitMs(300);
    }
    fs.copyFileSync(src, WALLET_PATH);
    appendLog(win || mainWindow, `[wallet] restored backup: ${src} -> ${WALLET_PATH}`);
    if (wasWalletdRunning) {
      const restarted = startWalletdOnRpc(win || mainWindow, targetRpc);
      if (!restarted.ok) return restarted;
    }
    queueWalletAutoSync(win || mainWindow, 'wallet-restore');
    return { ok: true, result: { restoredFrom: src, walletPath: WALLET_PATH } };
  } catch (err) {
    return { ok: false, error: String(err?.message || err) };
  }
}

function ensureValidatorsFile(win) {
  const validatorsPath = path.join(NODE_DATA_DIR, 'validators.txt');
  const LATTICE_KEY_HEX_LEN = 4096; // N=1024, 2 bytes each = 2048 bytes = 4096 hex chars

  // Validate existing file: every non-empty line must be exactly 4096 hex chars
  const isValidValidatorsContent = (text) => {
    const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
    if (!lines.length) return false;
    return lines.every(l => l.length === LATTICE_KEY_HEX_LEN && /^[0-9a-fA-F]+$/.test(l));
  };

  let needsSeed = false;

  if (!fs.existsSync(validatorsPath)) {
    fs.writeFileSync(validatorsPath, '', 'utf8');
    appendLog(win, `[setup] created validators file: ${validatorsPath}`);
    needsSeed = true;
  } else {
    try {
      const current = fs.readFileSync(validatorsPath, 'utf8').trim();
      if (!current) {
        needsSeed = true;
      } else if (!isValidValidatorsContent(current)) {
        appendLog(win, `[setup] validators file has invalid format (stale keys?), clearing: ${validatorsPath}`);
        fs.writeFileSync(validatorsPath, '', 'utf8');
        needsSeed = true;
      }
    } catch (e) {
      appendLog(win, `[warn] failed to read validators: ${String(e.message || e)}`);
      needsSeed = true;
    }
  }

  if (needsSeed) {
    try {
      const repoDefault = path.resolve(ROOT, '..', '..', 'testnet', 'validators.txt');
      if (fs.existsSync(repoDefault)) {
        const repoContent = fs.readFileSync(repoDefault, 'utf8').trim();
        if (repoContent && isValidValidatorsContent(repoContent)) {
          fs.copyFileSync(repoDefault, validatorsPath);
          appendLog(win, `[setup] seeded validators from: ${repoDefault}`);
        } else {
          appendLog(win, `[setup] repo validators also invalid, node will self-generate`);
        }
      }
    } catch (e) {
      appendLog(win, `[warn] failed to seed validators: ${String(e.message || e)}`);
    }
  }
  return validatorsPath;
}

async function ensureWalletExists() {
  if (fs.existsSync(WALLET_PATH)) return { ok: true, result: 'wallet exists' };
  if (fs.existsSync(NODE_KEY_PATH)) {
    const res = await runCli(['import-node-key', NODE_KEY_PATH, WALLET_PATH]);
    if (res.ok) return res;
  }
  return runCli(['create', WALLET_PATH]);
}

async function autoImportNodeKey(opts = {}) {
  const allowOverwrite = !!opts.allowOverwrite;
  const trigger = String(opts.trigger || 'auto').trim() || 'auto';
  if (!fs.existsSync(NODE_KEY_PATH)) return { ok: false, error: 'node key not found' };
  if (fs.existsSync(WALLET_PATH)) {
    const sz = Number(fs.statSync(WALLET_PATH).size || 0);
    if (sz > 0 && !allowOverwrite) {
      const msg = 'refusing auto-import over existing wallet (set KNOX_AUTO_IMPORT_ON_ADDRESS_PARSE_FAILURE=1 to allow)';
      appendLog(mainWindow, `[wallet] ${msg}; trigger=${trigger}; wallet=${WALLET_PATH}`);
      return { ok: false, error: msg };
    }
  }
  const backup = backupWalletSnapshot(mainWindow, 'auto-import-node-key', { minIntervalMs: 10 * 60 * 1000 });
  if (!backup.ok) return backup;
  return runCli(['import-node-key', NODE_KEY_PATH, WALLET_PATH]);
}

function ensureTls() {
  ensureDirs();
  if (fs.existsSync(CERT_PATH) && fs.existsSync(KEY_PATH)) {
    try {
      const existingKeyPem = fs.readFileSync(KEY_PATH, 'utf8');
      const keyObj = crypto.createPrivateKey(existingKeyPem);
      if (keyObj.asymmetricKeyType === 'rsa') {
        const bits = Number(keyObj.asymmetricKeyDetails?.modulusLength || 0);
        if (bits >= 2048) return { ok: true, result: 'tls exists' };
      } else if (typeof keyObj.asymmetricKeyType === 'string' && keyObj.asymmetricKeyType.length > 0) {
        return { ok: true, result: 'tls exists' };
      }
    } catch { }
  }

  const pems = selfsigned.generate(
    [{ name: 'commonName', value: '127.0.0.1' }],
    { days: 3650, algorithm: 'sha256', keySize: 2048 }
  );
  const keyObj = crypto.createPrivateKey(pems.private);
  const pkcs8Key = keyObj.export({ type: 'pkcs8', format: 'pem' });
  fs.writeFileSync(CERT_PATH, pems.cert);
  fs.writeFileSync(KEY_PATH, pkcs8Key);
  return { ok: true, result: 'tls regenerated' };
}

function readWalletdCa() {
  try {
    return fs.readFileSync(CERT_PATH);
  } catch {
    return null;
  }
}

function appendLog(win, line) {
  const stamped = `[${new Date().toISOString()}] ${line}`;
  try {
    ensureDirs();
    fs.appendFileSync(MAIN_LOG_PATH, `${stamped}\n`);
  } catch { }
  if (!win || win.isDestroyed()) return;
  win.webContents.send('log', stamped);
}

function emitWalletUpdated(win, reason = 'wallet-sync') {
  if (!win || win.isDestroyed()) return;
  win.webContents.send('wallet-updated', {
    reason: String(reason || 'wallet-sync'),
    atMs: Date.now()
  });
}

function recordRuntimeBlock(height, txs) {
  const stats = runtimeStats.node;
  const now = Date.now();
  if (height === 0) {
    stats.sealedCount = 0;
    stats.currentStreak = 0;
    stats.totalHardeningEstimate = 0;
    stats.recentBlocks = [];
  }
  const prevHeight = Number(stats.lastSealedHeight);
  stats.lastSealedHeight = height;
  stats.lastSealedAtMs = now;
  stats.sealedCount = Number(stats.sealedCount || 0) + 1;
  const diffBits = Number(stats.currentDifficultyBits || 0);
  if (Number.isFinite(diffBits) && diffBits > 0) {
    stats.totalHardeningEstimate = Number(stats.totalHardeningEstimate || 0) + diffBits;
  }
  if (Number.isFinite(prevHeight) && height === prevHeight + 1) {
    stats.currentStreak = Number(stats.currentStreak || 0) + 1;
  } else if (height === 0) {
    stats.currentStreak = 1;
  } else {
    stats.currentStreak = 1;
  }
  stats.recentBlocks = [
    {
      height,
      txs,
      status: 'SEALED',
      source: 'local-node',
      atMs: now,
      time: new Date(now).toLocaleTimeString()
    },
    ...stats.recentBlocks
  ].slice(0, 30);
}

function recordPendingReward(height, rewards = {}) {
  const stats = runtimeStats.node;
  const minerAddress = parseKnoxAddress(stats.minerAddress || desktopMinerAddress || '');
  const treasuryAddress = parseKnoxAddress(process.env.KNOX_MAINNET_TREASURY_ADDRESS || '');
  const devAddress = parseKnoxAddress(process.env.KNOX_MAINNET_DEV_ADDRESS || '');
  const premineAddress = parseKnoxAddress(process.env.KNOX_MAINNET_PREMINE_ADDRESS || '');
  const addressAmounts = {};
  const addAmount = (address, amount) => {
    const atoms = Number(amount || 0);
    if (!address || !Number.isFinite(atoms) || atoms <= 0) return;
    addressAmounts[address] = Number(addressAmounts[address] || 0) + atoms;
  };
  addAmount(minerAddress, rewards.miner);
  addAmount(treasuryAddress, rewards.treasury);
  addAmount(devAddress, rewards.dev);
  addAmount(premineAddress, rewards.premine);
  const total = Object.values(addressAmounts).reduce((sum, atoms) => sum + Number(atoms || 0), 0);
  if (!Number.isFinite(total) || total <= 0) return;
  const pending = Array.isArray(stats.pendingRewardEvents) ? stats.pendingRewardEvents : [];
  const filtered = pending.filter((entry) => Number(entry?.height || -1) !== Number(height));
  filtered.push({
    height: Number(height || 0),
    atMs: Date.now(),
    total,
    addressAmounts
  });
  filtered.sort((a, b) => Number(a.height || 0) - Number(b.height || 0));
  stats.pendingRewardEvents = filtered.slice(-128);
}

function trimPendingRewards(walletHeight = 0) {
  const stats = runtimeStats.node;
  const confirmedHeight = Number(walletHeight || 0);
  if (!Number.isFinite(confirmedHeight) || confirmedHeight <= 0) return;
  stats.pendingRewardEvents = (stats.pendingRewardEvents || []).filter(
    (entry) => Number(entry?.height || 0) > confirmedHeight
  );
}

function pendingRewardsForAddresses(indexedEntries = []) {
  const pendingEvents = Array.isArray(runtimeStats.node.pendingRewardEvents)
    ? runtimeStats.node.pendingRewardEvents
    : [];
  const byAddress = {};
  let total = 0;
  for (const entry of pendingEvents) {
    const addressAmounts = entry?.addressAmounts || {};
    for (const [address, amount] of Object.entries(addressAmounts)) {
      const atoms = Number(amount || 0);
      if (!address || !Number.isFinite(atoms) || atoms <= 0) continue;
      byAddress[address] = Number(byAddress[address] || 0) + atoms;
      total += atoms;
    }
  }
  const bySubaddress = {};
  for (const entry of indexedEntries) {
    const address = String(entry?.address || '').trim();
    const index = Number(entry?.index);
    if (!address || !Number.isFinite(index)) continue;
    const atoms = Number(byAddress[address] || 0);
    if (atoms > 0) bySubaddress[index] = atoms;
  }
  return { total, bySubaddress };
}

function queueWalletAutoSync(win, reason = 'sealed block') {
  if (!service.walletd) return;
  if (walletAutoSyncTimer) clearTimeout(walletAutoSyncTimer);
  walletAutoSyncTimer = setTimeout(() => {
    walletAutoSyncTimer = null;
    void runWalletAutoSync(win, reason);
  }, 1200);
}

async function runWalletAutoSync(win, reason = 'sealed block') {
  if (!service.walletd) return;
  if (walletAutoSyncInFlight) {
    walletAutoSyncQueued = true;
    return;
  }
  walletAutoSyncInFlight = true;
  try {
    const out = await walletdCall('/sync', {}, { timeoutMs: 30000 });
    runtimeStats.walletd.lastInfoAtMs = Date.now();
    if (out?.ok) {
      runtimeStats.walletd.lastInfoError = '';
      runtimeStats.walletd.lastSyncError = '';
      walletAutoSyncFailCount = 0;
      emitWalletUpdated(win || mainWindow, `auto-sync:${reason}`);
    } else {
      runtimeStats.walletd.lastSyncError = String(out?.error || 'sync failed');
      appendLog(win || mainWindow, `[walletd] auto-sync (${reason}) failed: ${runtimeStats.walletd.lastSyncError}`);
      walletAutoSyncFailCount += 1;
      const now = Date.now();
      const canFallback = now - walletAutoSyncFallbackAtMs >= 60000;
      if (isTimeoutErrorText(out?.error) && walletAutoSyncFailCount >= 2 && canFallback) {
        walletAutoSyncFallbackAtMs = now;
        await fallbackCliSyncAndReloadWalletd(win, `auto-sync ${reason}`);
        walletAutoSyncFailCount = 0;
      }
    }
  } catch (err) {
    runtimeStats.walletd.lastSyncError = String(err?.message || err);
    appendLog(win || mainWindow, `[walletd] auto-sync (${reason}) threw: ${runtimeStats.walletd.lastSyncError}`);
    walletAutoSyncFailCount += 1;
    const now = Date.now();
    const canFallback = now - walletAutoSyncFallbackAtMs >= 60000;
    if (isTimeoutErrorText(runtimeStats.walletd.lastSyncError) && walletAutoSyncFailCount >= 2 && canFallback) {
      walletAutoSyncFallbackAtMs = now;
      await fallbackCliSyncAndReloadWalletd(win, `auto-sync throw ${reason}`);
      walletAutoSyncFailCount = 0;
    }
  } finally {
    walletAutoSyncInFlight = false;
    if (walletAutoSyncQueued) {
      walletAutoSyncQueued = false;
      queueWalletAutoSync(win, 'queued');
    }
  }
}

function parseRuntimeLine(key, line, win) {
  if (!line) return;
  if (key === 'node') {
    const miningRuntimeErr = line.match(/mining_runtime_error\s+(.+)$/i);
    if (miningRuntimeErr) {
      runtimeStats.node.fallbackActive = true;
      runtimeStats.node.lastBackendError = String(miningRuntimeErr[1] || 'runtime error')
        .replace(/_/g, ' ')
        .trim();
      return;
    }
    const miningRuntime = line.match(/mining_runtime\s+(.+)$/i);
    if (miningRuntime) {
      const payload = String(miningRuntime[1] || '').trim();
      const fields = {};
      for (const token of payload.split(/\s+/)) {
        const idx = token.indexOf('=');
        if (idx <= 0) continue;
        const k = token.slice(0, idx);
        const v = token.slice(idx + 1);
        fields[k] = v;
      }
      runtimeStats.node.activeBackend = String(fields.active || runtimeStats.node.activeBackend || 'cpu');
      runtimeStats.node.configuredBackend = String(fields.configured || runtimeStats.node.configuredBackend || 'auto');
      runtimeStats.node.miningMode = String(fields.mode || runtimeStats.node.miningMode || 'hybrid');
      runtimeStats.node.availableBackends = String(fields.available || 'cpu')
        .split('|')
        .map((v) => String(v || '').trim())
        .filter((v) => v && v !== 'none');
      if (!runtimeStats.node.availableBackends.length) {
        runtimeStats.node.availableBackends = ['cpu'];
      }
      runtimeStats.node.activeDevice = String(fields.device || runtimeStats.node.activeDevice || 'cpu-main');
      runtimeStats.node.fallbackActive = String(fields.fallback || '0') === '1';
      runtimeStats.node.lastBackendError = fields.warning && fields.warning !== 'none'
        ? String(fields.warning).replace(/_/g, ' ')
        : '';
      return;
    }
    const propose = line.match(/propose attempt h=(\d+)\s+r=(\d+)/i);
    if (propose) {
      runtimeStats.node.lastProposeHeight = Number(propose[1]);
      runtimeStats.node.lastProposeRound = Number(propose[2]);
      runtimeStats.node.lastProposeAtMs = Date.now();
      return;
    }
    const ledgerTip = line.match(/\[knox-node\] ledger tip h=(\d+) hardening=(\d+)/);
    if (ledgerTip) {
      const h = Number(ledgerTip[1]);
      const hard = Number(ledgerTip[2]);
      if (h > 0) runtimeStats.node.lastSealedHeight = h;
      if (hard > 0) runtimeStats.node.totalHardeningEstimate = hard;
      return;
    }
    const sealedGenesis = line.match(/sealed genesis block.*txs=(\d+)(?:\s+rewards miner=(\d+)\s+treasury=(\d+)\s+dev=(\d+)\s+premine=(\d+))?/i);
    if (sealedGenesis) {
      recordRuntimeBlock(0, Number(sealedGenesis[1] || 0));
      recordPendingReward(0, {
        miner: Number(sealedGenesis[2] || 0),
        treasury: Number(sealedGenesis[3] || 0),
        dev: Number(sealedGenesis[4] || 0),
        premine: Number(sealedGenesis[5] || 0)
      });
      emitWalletUpdated(win || mainWindow, 'sealed:genesis');
      queueWalletAutoSync(win, 'genesis');
      return;
    }
    const sealed = line.match(/sealed block\s+(\d+)\s+txs=(\d+)(?:\s+rewards miner=(\d+)\s+treasury=(\d+)\s+dev=(\d+)\s+premine=(\d+))?/i);
    if (sealed) {
      recordRuntimeBlock(Number(sealed[1]), Number(sealed[2] || 0));
      recordPendingReward(Number(sealed[1]), {
        miner: Number(sealed[3] || 0),
        treasury: Number(sealed[4] || 0),
        dev: Number(sealed[5] || 0),
        premine: Number(sealed[6] || 0)
      });
      emitWalletUpdated(win || mainWindow, `sealed:${sealed[1]}`);
      queueWalletAutoSync(win, `height ${sealed[1]}`);
      return;
    }
    const reject = line.match(/reject proposal.*?:\s*(.+)$/i);
    if (reject) {
      runtimeStats.node.lastReject = String(reject[1] || '').trim();
      const missingParent = line.match(/reject proposal h=(\d+)\s+r=\d+:\s*missing parent block/i);
      if (missingParent) {
        const rejectHeight = Number(missingParent[1] || 0);
        if (shouldAutoResetLedgerFromReject(rejectHeight)) {
          appendLog(win, `[repair] stale-ledger pattern detected (local_h=${runtimeStats.node.lastSealedHeight || 0}, reject_h=${rejectHeight})`);
          setTimeout(() => {
            resetLocalLedgerAndRestart(win, `missing-parent@h${rejectHeight}`)
              .then((res) => {
                if (!res?.ok) appendLog(win, `[repair] auto reset failed: ${res?.error || 'unknown'}`);
              })
              .catch((err) => appendLog(win, `[repair] auto reset crashed: ${String(err?.message || err)}`));
          }, 0);
        }
      }
      return;
    }
  }
  if (key === 'walletd') {
    if (/listening on/i.test(line)) {
      runtimeStats.walletd.listening = true;
      runtimeStats.walletd.lastInfoAtMs = Date.now();
      return;
    }
    const syncErr = line.match(/sync failed:\s*(.+)$/i);
    if (syncErr) {
      runtimeStats.walletd.lastSyncError = String(syncErr[1] || '').trim();
      return;
    }
    if (/unauthorized|connect ECONNREFUSED|request timeout/i.test(line)) {
      runtimeStats.walletd.lastInfoError = line;
    }
  }
}

function formatExitHint(code) {
  if (code === 3221225477) {
    return 'access violation (0xC0000005). This means a native runtime crash (binary incompatibility OR a bug inside native code).';
  }
  return '';
}

function buildServiceEnv(key, envExtra = {}) {
  const merged = { ...process.env, ...envExtra };
  if ((key === 'node' || key === 'walletd') && !DESKTOP_INSECURE_DEV) {
    for (const k of CONSENSUS_SAFE_ENV_KEYS) {
      delete merged[k];
    }
    if (MAINNET_LOCKED) {
      // Packaged builds must never inherit stale shell overrides for consensus keys.
      for (const k of MAINNET_LOCK_STRIP_ENV_KEYS) {
        delete merged[k];
      }
      merged.KNOX_MAINNET_LOCK = '1';
      merged.KNOX_DISABLE_MAINNET_ENV_LOCK = '0';
    }
  }
  if (key === 'node') {
    // Desktop catch-up needs deterministic upstream sync settings regardless of shell state.
    merged.KNOX_NODE_UPSTREAM_SYNC_BATCH_COUNT = String(DESKTOP_UPSTREAM_SYNC_BATCH);
    merged.KNOX_NODE_UPSTREAM_SYNC_TIMEOUT_MS = String(DESKTOP_UPSTREAM_SYNC_TIMEOUT_MS);
    merged.KNOX_P2P_PROTOCOL_VERSION = String(MIN_SUPPORTED_P2P_PROTOCOL_VERSION);
  }
  if (key === 'walletd') {
    merged.KNOX_UPSTREAM_PROBE_TIMEOUT_MS = String(UPSTREAM_PROBE_TIMEOUT_MS);
    merged.KNOX_WALLETD_NETWORK_TIMEOUT_MS = String(WALLETD_NETWORK_TIMEOUT_MS);
    merged.KNOX_UPSTREAM_RPC_CONNECT_TIMEOUT_MS = String(UPSTREAM_RPC_CONNECT_TIMEOUT_MS);
    merged.KNOX_UPSTREAM_RPC_IO_TIMEOUT_MS = String(UPSTREAM_RPC_IO_TIMEOUT_MS);
  }
  return merged;
}

function spawnSvc(win, key, bin, args, envExtra = {}) {
  if (appShuttingDown) return { ok: false, error: `refusing to start ${key}: app is shutting down` };
  if (service[key]) return { ok: true, result: `${key} already running` };
  if (key === 'node') clearStaleNodeRpcPortOwner(win);
  if (!fs.existsSync(bin)) {
    const msg = `Missing binary: ${bin}`;
    appendLog(win, `[error] ${key}: ${msg}`);
    return { ok: false, error: msg };
  }
  const finalEnv = buildServiceEnv(key, envExtra);
  const p = spawn(bin, args, {
    cwd: USER_DIR,
    windowsHide: true,
    env: finalEnv
  });
  service[key] = p;
  if (key === 'node') {
    runtimeStats.node.running = true;
    runtimeStats.node.minerAddress =
      Array.isArray(args) && args.length > 5 && /^knox1[a-f0-9]{32,}$/i.test(String(args[5] || ''))
        ? String(args[5] || '')
        : '';
  }
  if (key === 'walletd') {
    runtimeStats.walletd.running = true;
    runtimeStats.walletd.listening = false;
  }
  if (key === 'walletd') {
    walletdRpcTarget = args?.[1] || null;
  }
  appendLog(win, `[spawn] ${key}: ${bin} ${args.join(' ')}`);
  const onData = (d) => {
    const text = String(d || '');
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.trim();
      if (!line) continue;
      parseRuntimeLine(key, line, win);
      appendLog(win, `[${key}] ${line}`);
    }
  };
  p.stdout.on('data', onData);
  p.stderr.on('data', onData);
  p.on('exit', (code, sig) => {
    appendLog(win, `[exit] ${key}: code=${code} signal=${sig || 'none'}`);
    const hint = formatExitHint(code);
    if (hint) appendLog(win, `[error] ${key}: ${hint}`);
    lastExit[key] = {
      code,
      signal: sig || 'none',
      hint
    };
    // Ignore stale exit events from older processes after a restart.
    if (service[key] !== p) return;
    service[key] = null;
    if (key === 'node') {
      runtimeStats.node.running = false;
      resetRuntimeMiningSession();
    }
    if (key === 'walletd') {
      runtimeStats.walletd.running = false;
      runtimeStats.walletd.listening = false;
      if (walletAutoSyncTimer) clearTimeout(walletAutoSyncTimer);
      walletAutoSyncTimer = null;
      walletAutoSyncInFlight = false;
      walletAutoSyncQueued = false;
      walletAutoSyncFailCount = 0;
    }
    if (key === 'walletd') walletdRpcTarget = null;
  });
  return { ok: true, result: `${key} started` };
}

function clearStaleNodeRpcPortOwner(win) {
  if (process.platform !== 'win32') return;
  const m = String(LOCAL_NODE_RPC || '').match(/:(\d+)$/);
  if (!m) return;
  const port = m[1];
  let netstat = '';
  try {
    netstat = String(execSync(`netstat -ano -p tcp | findstr :${port}`, { encoding: 'utf8' }) || '');
  } catch {
    return;
  }
  const lines = netstat.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
  for (const line of lines) {
    const parts = line.split(/\s+/);
    if (parts.length < 5) continue;
    const local = parts[1] || '';
    const state = parts[3] || '';
    const pidRaw = parts[4] || '';
    if (!/LISTENING/i.test(state)) continue;
    if (!local.endsWith(`:${port}`)) continue;
    if (!/^\d+$/.test(pidRaw)) continue;
    const pid = Number(pidRaw);
    if (!Number.isFinite(pid) || pid <= 0) continue;
    if (service.node && service.node.pid === pid) continue;

    let taskInfo = '';
    try {
      taskInfo = String(execSync(`tasklist /FI "PID eq ${pid}" /FO CSV /NH`, { encoding: 'utf8' }) || '');
    } catch {
      taskInfo = '';
    }
    if (!/knox-node\.exe/i.test(taskInfo)) {
      appendLog(win, `[warn] rpc ${LOCAL_NODE_RPC} in use by pid=${pid}; not killing non-node process`);
      continue;
    }
    appendLog(win, `[setup] freeing stale knox-node pid=${pid} on rpc ${LOCAL_NODE_RPC}`);
    try {
      execSync(`taskkill /F /T /PID ${pid}`, { stdio: 'pipe' });
    } catch (err) {
      appendLog(win, `[warn] failed to kill stale pid=${pid}: ${String(err?.message || err)}`);
    }
  }
}

function stopSvc(key) {
  const p = service[key];
  if (!p) return { ok: true, result: `${key} not running` };
  try {
    if (process.platform === 'win32') {
      // Use synchronous taskkill so restart paths don't race the old process.
      try {
        execSync(`taskkill /F /T /PID ${p.pid}`, { stdio: 'pipe' });
      } catch {
        try { p.kill(); } catch { }
      }
    } else {
      p.kill();
    }
  } catch { }
  service[key] = null;
  if (key === 'node') {
    runtimeStats.node.running = false;
    resetRuntimeMiningSession();
  }
  if (key === 'walletd') {
    runtimeStats.walletd.running = false;
    runtimeStats.walletd.listening = false;
    if (walletAutoSyncTimer) clearTimeout(walletAutoSyncTimer);
    walletAutoSyncTimer = null;
    walletAutoSyncInFlight = false;
    walletAutoSyncQueued = false;
    walletAutoSyncFailCount = 0;
  }
  if (key === 'walletd') walletdRpcTarget = null;
  return { ok: true, result: `${key} stopped` };
}

let appShuttingDown = false;
function shutdownLocalServices() {
  appShuttingDown = true;
  stopSvc('node');
  stopSvc('walletd');
  if (process.platform === 'win32') {
    // Belt-and-suspenders cleanup so closing the wallet cannot leave local mining behind.
    for (const image of ['knox-node.exe', 'knox-wallet.exe']) {
      try {
        execSync(`taskkill /F /T /IM ${image}`, { stdio: 'pipe' });
      } catch {
        // Ignore "not found" and continue.
      }
    }
  }
}

function runCli(args, options = {}) {
  const timeoutMs = options.timeoutMs || 10000;
  return new Promise((resolve) => {
    const bin = resolveBin('knox-wallet-cli.exe');
    if (!fs.existsSync(bin)) {
      const searched = binCandidates('knox-wallet-cli.exe').join(', ');
      resolve({ ok: false, error: `wallet CLI missing: ${bin}; searched: ${searched}` });
      return;
    }
    const p = spawn(bin, args, { cwd: USER_DIR, windowsHide: true, env: { ...process.env, ...options.env } });
    let out = '';
    const timer = setTimeout(() => {
      p.kill();
      resolve({ ok: false, error: `wallet CLI timeout after ${timeoutMs}ms` });
    }, timeoutMs);

    p.stdout.on('data', (d) => (out += String(d)));
    p.stderr.on('data', (d) => (out += String(d)));
    p.on('exit', (code) => {
      clearTimeout(timer);
      if (code === 0) resolve({ ok: true, result: out.trim() || 'ok' });
      else resolve({ ok: false, error: out.trim() || `failed (${code})` });
    });
    p.on('error', (err) => {
      clearTimeout(timer);
      resolve({ ok: false, error: String(err.message || err) });
    });
  });
}

async function walletInfoFromCli() {
  const [addrRes, balRes, addrsRes, balancesRes] = await Promise.all([
    runCli(['address', WALLET_PATH]),
    runCli(['balance', WALLET_PATH]),
    runCli(['addresses', WALLET_PATH]),
    walletBalancesFromCli(),
  ]);

  const addressText = String(addrRes?.result || '');
  const mAddr = addressText.match(/knox1[a-f0-9]{32,}/i);
  let address = mAddr ? mAddr[0] : '';

  const balText = String(balRes?.result || '');
  const mAtoms = balText.match(/\((\d+)\)/);
  const fallbackBalance = mAtoms ? Number(mAtoms[1]) : 0;
  const balancesInfo = balancesRes?.ok
    ? balancesRes.result
    : { totalBalance: fallbackBalance, subaddressBalances: {}, addresses: [] };
  const balance = Number.isFinite(Number(balancesInfo.totalBalance))
    ? Number(balancesInfo.totalBalance)
    : fallbackBalance;

  const addresses = [];
  const lines = String(addrsRes?.result || '').split(/\r?\n/);
  for (const line of lines) {
    const m = line.match(/knox1[a-f0-9]{32,}/i);
    if (m) addresses.push(m[0]);
  }
  if (Array.isArray(balancesInfo.addresses)) {
    for (const entry of balancesInfo.addresses) {
      if (entry?.address) addresses.push(String(entry.address));
    }
  }
  if (!addresses.length && address) addresses.push(address);

  if (!address && !addresses.length) {
    if (AUTO_IMPORT_ON_ADDRESS_PARSE_FAILURE) {
      const imported = await autoImportNodeKey({ allowOverwrite: false, trigger: 'walletInfoFromCli' });
      if (imported.ok) {
        const retryAddr = await runCli(['address', WALLET_PATH]);
        const retryText = String(retryAddr?.result || '');
        const mRetry = retryText.match(/knox1[a-f0-9]{32,}/i);
        if (mRetry) {
          address = mRetry[0];
          addresses.push(address);
        }
      }
    } else {
      appendLog(mainWindow, '[wallet] address parse failed; auto-import disabled');
    }
  }

  if (!address && !addresses.length) {
    return { ok: false, error: 'wallet info unavailable (wallet daemon down and CLI parse failed)' };
  }
  return {
    ok: true,
    result: {
      address: address || addresses[0] || '',
      balance,
      last_height: 0,
      addresses: Array.from(new Set(addresses)),
      subaddressBalances: balancesInfo.subaddressBalances || {}
    }
  };
}

function parseCliAddressLines(text) {
  const result = [];
  const lines = String(text || '').split(/\r?\n/);
  for (const line of lines) {
    const indexed = line.match(/#(\d+):\s*(knox1[a-f0-9]{32,})/i);
    if (indexed) {
      result.push({ index: Number(indexed[1]), address: indexed[2] });
      continue;
    }
    const plain = line.match(/knox1[a-f0-9]{32,}/i);
    if (plain) result.push({ index: result.length, address: plain[0] });
  }
  return result;
}

function parseCliBalances(text) {
  const result = {
    totalBalance: 0,
    subaddressBalances: {},
    addresses: []
  };
  const lines = String(text || '').split(/\r?\n/);
  for (const line of lines) {
    const entry = line.match(/#(\d+):\s*(knox1[a-f0-9]{32,})\s*\|\s*[^(]+\((\d+)\)/i);
    if (entry) {
      const index = Number(entry[1]);
      const address = entry[2];
      const atoms = Number(entry[3] || 0);
      if (Number.isFinite(index)) result.subaddressBalances[index] = atoms;
      if (address) result.addresses.push({ index, address });
      continue;
    }
    const total = line.match(/Total:\s*[^(]+\((\d+)\)/i);
    if (total) result.totalBalance = Number(total[1] || 0);
  }
  return result;
}

async function walletBalancesFromCli() {
  const out = await runCli(['balances', WALLET_PATH]);
  if (!out.ok) return { ok: false, error: out.error || 'wallet balances unavailable' };
  return { ok: true, result: parseCliBalances(out.result) };
}

async function walletIndexedAddressesFromCli() {
  let out = await runCli(['addresses', WALLET_PATH]);
  let result = out.ok ? parseCliAddressLines(out.result) : [];

  if (!result.length) {
    if (AUTO_IMPORT_ON_ADDRESS_PARSE_FAILURE) {
      const imported = await autoImportNodeKey({ allowOverwrite: false, trigger: 'walletIndexedAddressesFromCli' });
      if (imported.ok) {
        out = await runCli(['addresses', WALLET_PATH]);
        result = out.ok ? parseCliAddressLines(out.result) : [];
      }
    } else {
      appendLog(mainWindow, '[wallet] addresses parse failed; auto-import disabled');
    }
  }

  if (!result.length) {
    return { ok: false, error: 'wallet addresses unavailable (wallet daemon down and CLI parse failed)' };
  }
  return { ok: true, result };
}

async function walletdCall(pathname, body, options = {}) {
  // Give walletd more headroom under load so transient RPC latency does not look like a disconnect.
  const timeoutMs = Math.max(1000, Number(options.timeoutMs || 10000));
  const suppressAutoRecover = !!options.suppressAutoRecover;
  const retryOnRefused = options.retryOnRefused !== false;

  const callOnce = () =>
    new Promise((resolve) => {
      const [host, portStr] = WALLETD_BIND.split(':');
      const ca = readWalletdCa();
      if (!ca) {
        resolve({ ok: false, error: 'walletd TLS cert missing; run Generate TLS' });
        return;
      }
      const hostLower = String(host || 'localhost').toLowerCase();
      const isLocal = hostLower === '127.0.0.1' || hostLower === 'localhost' || hostLower === '::1';
      const servername = isLocal ? undefined : (hostLower === '127.0.0.1' || hostLower === '::1') ? 'localhost' : hostLower;

      const req = https.request(
        {
          host,
          port: Number(portStr),
          path: pathname,
          method: body ? 'POST' : 'GET',
          rejectUnauthorized: !isLocal,
          ca,
          minVersion: 'TLSv1.2',
          servername: servername,
          headers: {
            'Authorization': `Bearer ${TOKEN}`,
            'Content-Type': 'application/json'
          }
        },
        (res) => {
          let raw = '';
          res.on('data', (d) => (raw += String(d)));
          res.on('end', () => {
            try {
              const parsed = raw ? JSON.parse(raw) : {};
              const httpOk = res.statusCode >= 200 && res.statusCode < 300;
              // walletd wraps payloads as { ok, result, error }; flatten here for renderer.
              if (
                parsed &&
                typeof parsed === 'object' &&
                Object.prototype.hasOwnProperty.call(parsed, 'ok') &&
                Object.prototype.hasOwnProperty.call(parsed, 'result')
              ) {
                resolve({
                  ok: httpOk && !!parsed.ok,
                  status: res.statusCode,
                  result: parsed.result,
                  error: parsed.error || raw || `http ${res.statusCode}`
                });
                return;
              }
              resolve({ ok: httpOk, status: res.statusCode, result: parsed, error: parsed.error || raw || `http ${res.statusCode}` });
            } catch {
              resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, result: raw, error: raw || `http ${res.statusCode}` });
            }
          });
        }
      );
      req.setTimeout(timeoutMs, () => {
        req.destroy(new Error('walletd request timeout'));
      });
      req.on('error', (e) => resolve({ ok: false, error: String(e.message || e) }));
      if (body) req.write(JSON.stringify(body));
      req.end();
    });

  let out = await callOnce();
  if (out.ok) return out;
  if (suppressAutoRecover || !retryOnRefused || !isConnRefusedErrorText(out.error)) return out;

  const recovered = await recoverWalletdIfRefused(pathname);
  if (!recovered.ok) {
    return {
      ...out,
      error: `${String(out.error || 'walletd call failed')}; auto-recover failed: ${String(recovered.error || 'unknown')}`
    };
  }

  out = await callOnce();
  if (out.ok) {
    appendLog(mainWindow, `[repair] walletd recovered after connection refusal; retried ${pathname}`);
  }
  return out;
}

function walletdRpcAddr() {
  if (USE_LOCAL_RPC_WHEN_NODE_RUNNING && service.node) return LOCAL_NODE_RPC;
  return RPC_UPSTREAM || LOCAL_NODE_RPC;
}

function walletSyncRpcAddr() {
  if (USE_LOCAL_RPC_WHEN_NODE_RUNNING && service.node) return LOCAL_NODE_RPC;
  return walletdRpcTarget || walletdRpcAddr() || LOCAL_NODE_RPC;
}

function startWalletdOnRpc(win, rpcAddr) {
  const walletBin = resolveBin('knox-wallet.exe');
  const normalizedRpc = normalizeRpcEndpoint(rpcAddr, DEFAULT_PUBLIC_RPC_CANDIDATES[0]);
  if (service.walletd && normalizeRpcEndpoint(walletdRpcTarget || '', '') === normalizedRpc) {
    return { ok: true, result: `walletd already running on ${normalizedRpc}` };
  }
  if (String(rpcAddr || '').trim() !== normalizedRpc) {
    appendLog(win, `[config] normalized wallet RPC target "${String(rpcAddr || '').trim()}" -> "${normalizedRpc}"`);
  }
  return spawnSvc(win, 'walletd', walletBin, [WALLET_PATH, normalizedRpc, WALLETD_BIND], {
    KNOX_WALLETD_TOKEN: TOKEN,
    KNOX_WALLETD_TLS_CERT: CERT_PATH,
    KNOX_WALLETD_TLS_KEY: KEY_PATH,
    // Give walletd->node RPC more headroom under mining load.
    KNOX_RPC_CONNECT_TIMEOUT_MS: String(UPSTREAM_RPC_CONNECT_TIMEOUT_MS),
    KNOX_RPC_IO_TIMEOUT_MS: String(UPSTREAM_RPC_IO_TIMEOUT_MS)
  });
}

async function waitForWalletdReady(timeoutMs = 5000, opts = {}) {
  const suppressAutoRecover = !!opts.suppressAutoRecover;
  const deadline = Date.now() + Math.max(1000, timeoutMs);
  while (Date.now() < deadline) {
    if (!service.walletd) return false;
    const probe = await walletdCall('/health', null, {
      timeoutMs: 1200,
      suppressAutoRecover,
      retryOnRefused: !suppressAutoRecover
    });
    if (probe.ok) return true;
    await waitMs(150);
  }
  return false;
}

async function recoverWalletdIfRefused(pathname = '/unknown') {
  if (walletdAutoRecoverPromise) return walletdAutoRecoverPromise;
  walletdAutoRecoverPromise = (async () => {
    const target = normalizeRpcEndpoint(walletdRpcTarget || walletdRpcAddr(), DEFAULT_PUBLIC_RPC_CANDIDATES[0]);
    appendLog(
      mainWindow,
      `[repair] walletd connection refused on ${pathname}; restarting wallet daemon on ${target}`
    );
    if (service.walletd) {
      stopSvc('walletd');
      await waitMs(300);
    }
    const started = startWalletdOnRpc(mainWindow, target);
    if (!started.ok) return started;
    const ready = await waitForWalletdReady(6000, { suppressAutoRecover: true });
    if (!ready) return { ok: false, error: failedServiceStart('walletd') };
    return { ok: true, result: target };
  })();
  try {
    return await walletdAutoRecoverPromise;
  } finally {
    walletdAutoRecoverPromise = null;
  }
}

async function waitForRemoteTipVisible(win, minTip = 1, timeoutMs = 25000) {
  const deadline = Date.now() + Math.max(3000, Number(timeoutMs) || 25000);
  let lastErr = '';
  const tipProbeTimeoutMs = Math.min(15000, Math.max(6000, UPSTREAM_PROBE_TIMEOUT_MS));
  while (Date.now() < deadline) {
    const probe = await walletdCall('/upstream-tip', null, { timeoutMs: tipProbeTimeoutMs });
    if (probe.ok && probe.result) {
      const tip = Number(probe.result.tip_height ?? 0);
      if (Number.isFinite(tip) && tip >= minTip) {
        lastUpstreamTipSeen = Math.max(lastUpstreamTipSeen, tip);
        appendLog(win, `[sync] upstream tip visible h=${tip}; mining gate opened`);
        return { ok: true, result: tip };
      }
      lastErr = `tip=${tip}`;
    } else {
      lastErr = String(probe.error || 'upstream tip unavailable');
    }
    await waitMs(1000);
  }
  return { ok: false, error: `upstream tip not visible before timeout (${lastErr || 'unknown'})` };
}

async function ensureWalletdUpstreamConnected(win, probeTimeoutMs = UPSTREAM_PROBE_TIMEOUT_MS, opts = {}) {
  if (walletdSwitchPromise) {
    return walletdSwitchPromise;
  }
  walletdSwitchPromise = (async () => {
    let candidates = rpcCandidateList();
    const current = normalizeRpcEndpoint(walletdRpcTarget || '', '');
    if (opts.excludeCurrent && current) {
      candidates = candidates.filter((ep) => ep !== current);
    }
    if (opts.preferCurrent && current) {
      candidates = [current, ...candidates.filter((ep) => ep !== current)];
    }
    if (!candidates.length && current) candidates = [current];
    let lastErr = 'no rpc candidates';
    let endpointIndex = 0;
    for (const ep of candidates) {
      endpointIndex += 1;
      if (service.walletd) {
        stopSvc('walletd');
        await waitMs(300);
      }
      const started = startWalletdOnRpc(win, ep);
      if (!started.ok) {
        lastErr = String(started.error || `failed to start walletd on ${ep}`);
        continue;
      }
      const ready = await waitForWalletdReady(5000);
      if (!ready) {
        lastErr = failedServiceStart('walletd');
        continue;
      }
      let connected = false;
      let connectedTip = 0;
      for (let attempt = 1; attempt <= UPSTREAM_PROBE_ATTEMPTS; attempt++) {
        const probe = await walletdCall('/upstream-tip', null, { timeoutMs: probeTimeoutMs });
        if (probe.ok) {
          connectedTip = Number(probe?.result?.tip_height ?? 0);
          if (!Number.isFinite(connectedTip) || connectedTip < 0) connectedTip = 0;
          connected = true;
          break;
        }
        lastErr = String(probe.error || `probe failed on ${ep}`);
        appendLog(
          win,
          `[sync] walletd upstream probe failed on ${ep} (endpoint ${endpointIndex}/${candidates.length}, attempt ${attempt}/${UPSTREAM_PROBE_ATTEMPTS}): ${lastErr}`
        );
        await waitMs(1200);
      }
      if (connected) {
        if (
          lastUpstreamTipSeen > 0
          && connectedTip > 0
          && connectedTip + UPSTREAM_TIP_REGRESSION_TOLERANCE < lastUpstreamTipSeen
        ) {
          appendLog(
            win,
            `[sync] upstream ${ep} rejected as stale (tip=${connectedTip}, last_seen=${lastUpstreamTipSeen}, tolerance=${UPSTREAM_TIP_REGRESSION_TOLERANCE})`
          );
          lastErr = `stale endpoint tip=${connectedTip} < last_seen=${lastUpstreamTipSeen}`;
          continue;
        }
        if (connectedTip > 0) {
          lastUpstreamTipSeen = Math.max(lastUpstreamTipSeen, connectedTip);
        }
        appendLog(win, `[sync] walletd upstream connected via ${ep}`);
        return { ok: true, result: ep };
      }
    }
    return { ok: false, error: `no reachable upstream RPC endpoint (${lastErr})` };
  })();
  try {
    return await walletdSwitchPromise;
  } finally {
    walletdSwitchPromise = null;
  }
}

function clampInt(v, min, max, fallback) {
  const n = Number(v);
  if (!Number.isFinite(n)) return fallback;
  return Math.max(min, Math.min(max, Math.round(n)));
}

function normalizeMiningMode(v, fallback = 'hybrid') {
  const mode = String(v || fallback).toLowerCase();
  if (mode === 'cpu' || mode === 'gpu' || mode === 'hybrid') return mode;
  return fallback;
}

function normalizeMiningBackend(v, fallback = 'auto') {
  const backend = String(v || fallback).toLowerCase();
  if (backend === 'auto' || backend === 'cpu' || backend === 'opencl' || backend === 'cuda') {
    return backend;
  }
  return fallback;
}

function defaultMiningConfig() {
  return {
    mode: 'hybrid',
    backend: 'auto',
    preset: 'balanced',
    minerAddress: '',
    cpuCores: 12,
    cpuUtil: 70,
    gpuUtil: 70,
    vram: 60,
    gpuDeviceId: 0,
    cudaDeviceOrdinal: 0,
    scheduleEnabled: false,
    surgeAutoMax: false,
    tempThrottle: true,
    powerCostPerKwh: 0.12,
    profile: {
      mode: 'hybrid',
      backend: 'auto',
      difficultyBits: 6,
      seqSteps: 384,
      memoryBytes: 40 * 1024 * 1024,
      cpuUtil: 70,
      gpuUtil: 70,
      gpuDeviceId: 0,
      cudaDeviceOrdinal: 0
    }
  };
}

function loadMiningConfig() {
  ensureDirs();
  if (!fs.existsSync(MINING_CFG_PATH)) return defaultMiningConfig();
  try {
    const raw = fs.readFileSync(MINING_CFG_PATH, 'utf8');
    const cfg = { ...defaultMiningConfig() };
    for (const line of raw.split(/\r?\n/)) {
      const m = line.match(/^\s*([a-zA-Z0-9_]+)\s*=\s*(.+?)\s*$/);
      if (!m) continue;
      const k = m[1];
      let v = m[2];
      if (v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      else if (v === 'true' || v === 'false') v = v === 'true';
      else if (!Number.isNaN(Number(v))) v = Number(v);
      cfg[k] = v;
    }
    cfg.profile = {
      mode: normalizeMiningMode(cfg.mode, 'hybrid'),
      backend: normalizeMiningBackend(cfg.backend, 'auto'),
      difficultyBits: clampInt(cfg.difficultyBits, 1, 20, 6),
      seqSteps: clampInt(cfg.seqSteps, 16, 4096, 384),
      memoryBytes: clampInt(cfg.memoryBytes, 4 * 1024 * 1024, 256 * 1024 * 1024, 40 * 1024 * 1024),
      cpuUtil: clampInt(cfg.cpuUtil, 1, 100, 70),
      gpuUtil: clampInt(cfg.gpuUtil, 1, 100, 70),
      gpuDeviceId: clampInt(cfg.gpuDeviceId, 0, 128, 0),
      cudaDeviceOrdinal: clampInt(cfg.cudaDeviceOrdinal, 0, 128, 0),
    };
    cfg.backend = cfg.profile.backend;
    const miner = String(cfg.minerAddress || '').trim();
    cfg.minerAddress = /knox1[a-f0-9]{32,}/i.test(miner) ? miner : '';
    return cfg;
  } catch {
    return defaultMiningConfig();
  }
}

function saveMiningConfig(incoming) {
  ensureDirs();
  const existing = loadMiningConfig();
  const merged = { ...defaultMiningConfig(), ...existing, ...(incoming || {}) };
  const profile = incoming?.profile || existing.profile || defaultMiningConfig().profile;
  merged.profile = {
    mode: normalizeMiningMode(profile.mode || merged.mode, 'hybrid'),
    backend: normalizeMiningBackend(profile.backend || merged.backend, 'auto'),
    difficultyBits: clampInt(profile.difficultyBits, 1, 20, 6),
    seqSteps: clampInt(profile.seqSteps, 16, 4096, 384),
    memoryBytes: clampInt(profile.memoryBytes, 4 * 1024 * 1024, 256 * 1024 * 1024, 40 * 1024 * 1024),
    cpuUtil: clampInt(profile.cpuUtil, 1, 100, clampInt(merged.cpuUtil, 1, 100, 70)),
    gpuUtil: clampInt(profile.gpuUtil, 1, 100, clampInt(merged.gpuUtil, 1, 100, 70)),
    gpuDeviceId: clampInt(profile.gpuDeviceId, 0, 128, clampInt(merged.gpuDeviceId, 0, 128, 0)),
    cudaDeviceOrdinal: clampInt(
      profile.cudaDeviceOrdinal,
      0,
      128,
      clampInt(merged.cudaDeviceOrdinal, 0, 128, 0)
    ),
  };
  merged.mode = merged.profile.mode;
  merged.backend = merged.profile.backend;
  const lines = [
    '# KNOX mining config',
    `mode = "${normalizeMiningMode(merged.mode, 'hybrid')}"`,
    `backend = "${normalizeMiningBackend(merged.backend, 'auto')}"`,
    `preset = "${String(merged.preset || 'balanced').toLowerCase()}"`,
    `minerAddress = "${String(merged.minerAddress || '').trim()}"`,
    `cpuCores = ${clampInt(merged.cpuCores, 1, 128, 12)}`,
    `cpuUtil = ${clampInt(merged.cpuUtil, 1, 100, 70)}`,
    `gpuUtil = ${clampInt(merged.gpuUtil, 1, 100, 70)}`,
    `vram = ${clampInt(merged.vram, 1, 100, 60)}`,
    `gpuDeviceId = ${clampInt(merged.gpuDeviceId, 0, 128, 0)}`,
    `cudaDeviceOrdinal = ${clampInt(merged.cudaDeviceOrdinal, 0, 128, 0)}`,
    `scheduleEnabled = ${Boolean(merged.scheduleEnabled) ? 'true' : 'false'}`,
    `surgeAutoMax = ${Boolean(merged.surgeAutoMax) ? 'true' : 'false'}`,
    `tempThrottle = ${Boolean(merged.tempThrottle) ? 'true' : 'false'}`,
    `powerCostPerKwh = ${Number(merged.powerCostPerKwh || 0.12)}`,
    `difficultyBits = ${merged.profile.difficultyBits}`,
    `seqSteps = ${merged.profile.seqSteps}`,
    `memoryBytes = ${merged.profile.memoryBytes}`,
  ];
  fs.writeFileSync(MINING_CFG_PATH, `${lines.join('\n')}\n`, 'utf8');
  miningProfileState = merged.profile;
  desktopMinerAddress = String(merged.minerAddress || '').trim();
  return merged;
}

function nodeDesktopEnv(mine, profile = null, minLocalHeightForMining = 0, minerAddress = '') {
  const env = {
    KNOX_NODE_NO_MINE: mine ? '0' : '1',
    KNOX_P2P_PSK_SERVICE: process.env.KNOX_P2P_PSK_SERVICE || 'knox-p2p',
    KNOX_P2P_PSK_ACCOUNT: process.env.KNOX_P2P_PSK_ACCOUNT || 'desktop-local',
    KNOX_NODE_UPSTREAM_RPC: String(walletdRpcTarget || RPC_UPSTREAM || '').trim(),
    // Improve catch-up throughput for fresh users.
    KNOX_SYNC_BLOCKS_RESPONSE_MAX_BYTES: String(128 * 1024 * 1024),
    // Keep sync polling tight so out-of-window batches do not stall for long.
    KNOX_SYNC_RETRY_MS: '1000',
    KNOX_SYNC_STALL_MS: '4000',
    KNOX_NODE_UPSTREAM_SYNC_BATCH_COUNT: String(DESKTOP_UPSTREAM_SYNC_BATCH),
    KNOX_NODE_UPSTREAM_SYNC_TIMEOUT_MS: String(DESKTOP_UPSTREAM_SYNC_TIMEOUT_MS),
    KNOX_TRUST_SYNC_BLOCKS: '1'
  };
  if (MAINNET_LOCKED) {
    env.KNOX_MAINNET_LOCK = '1';
    const premineAddress =
      parseKnoxAddress(process.env.KNOX_MAINNET_PREMINE_ADDRESS || '') ||
      parseKnoxAddress(minerAddress) ||
      parseKnoxAddress(desktopMinerAddress || '');
    if (premineAddress) env.KNOX_MAINNET_PREMINE_ADDRESS = premineAddress;
    const treasuryAddress = parseKnoxAddress(process.env.KNOX_MAINNET_TREASURY_ADDRESS || '');
    if (treasuryAddress) env.KNOX_MAINNET_TREASURY_ADDRESS = treasuryAddress;
    const genesisHash = String(process.env.KNOX_MAINNET_GENESIS_HASH || DEFAULT_MAINNET_GENESIS_HASH)
      .trim()
      .toLowerCase();
    if (/^[0-9a-f]{64}$/.test(genesisHash)) {
      env.KNOX_MAINNET_GENESIS_HASH = genesisHash;
    }
  }
  const gateHeight = Number.isFinite(Number(minLocalHeightForMining))
    ? Math.max(0, Math.floor(Number(minLocalHeightForMining)))
    : 0;
  if (mine && gateHeight > 0) {
    env.KNOX_MIN_LOCAL_HEIGHT_FOR_MINING = String(gateHeight);
  } else {
    env.KNOX_MIN_LOCAL_HEIGHT_FOR_MINING = '0';
  }
  const isSolo = /^(1|true|yes)$/i.test(String(process.env.KNOX_DESKTOP_SOLO || '0'));
  const hasExternalPeers = ALLOW_NETWORK_ENV_OVERRIDES
    && (!!process.env.KNOX_PUBLIC_P2P_ADDR || !!process.env.KNOX_DESKTOP_LOCAL_PEERS);

  if (!MAINNET_LOCKED) {
    // Open-mining: do not enforce a hard peer-count gate in desktop.
    env.KNOX_MIN_PEERS_FOR_MINING = '0';
    env.KNOX_NODE_SKIP_VALIDATORS = '0';

    // Lattice KEM handles per-session encryption now.
    // Only forward user-supplied PSK if explicitly set; never use a hardcoded fallback.
    let psk = String(process.env.KNOX_P2P_PSK || '').replace(/^["']+|["']+$/g, '').trim();
    if (psk && psk.length === 64) {
      env.KNOX_P2P_PSK = psk;
    } else {
      // No PSK needed — lattice handshake derives the session key.
      // Keep transport encrypted by default; do not enable plaintext fallback.
    }
    // Allow migration of the ledger database if it was created with an older version.
    env.KNOX_DB_ALLOW_LEGACY_V1 = '1';
  }
  if (DESKTOP_INSECURE_DEV && !MAINNET_LOCKED) {
    env.KNOX_ALLOW_UNSAFE_OVERRIDES = '1';
    env.KNOX_LATTICE_MINING_DEBUG = '1';
  }
  if (!MAINNET_LOCKED && !USE_VALIDATORS_FILE_FOR_DESKTOP_NODE && (isSolo || !hasExternalPeers)) {
    env.KNOX_NODE_SKIP_VALIDATORS = '1';
  }
  if (profile && typeof profile === 'object') {
    const mode = normalizeMiningMode(profile.mode, 'hybrid');
    const backend = normalizeMiningBackend(profile.backend, 'auto');
    let diff = clampInt(profile.difficultyBits, 1, 20, 6);
    let seq = clampInt(profile.seqSteps, 16, 4096, 64);
    let mem = clampInt(profile.memoryBytes, 4 * 1024 * 1024, 256 * 1024 * 1024, 8 * 1024 * 1024);
    const cpuUtil = clampInt(profile.cpuUtil, 1, 100, 70);
    const gpuUtil = clampInt(profile.gpuUtil, 1, 100, 70);
    const gpuDeviceId = clampInt(profile.gpuDeviceId, 0, 128, 0);
    const cudaDeviceOrdinal = clampInt(profile.cudaDeviceOrdinal, 0, 128, 0);
    if (mode === 'cpu') {
      mem = Math.min(mem, 32 * 1024 * 1024);
      seq = Math.max(seq, 128);
      diff = Math.max(1, diff - 1);
    } else if (mode === 'gpu') {
      mem = Math.min(256 * 1024 * 1024, Math.max(mem, 32 * 1024 * 1024));
      seq = Math.max(64, Math.min(seq, 1024));
      diff = Math.max(1, diff - 2);
    }
    if (!MAINNET_LOCKED) {
      env.KNOX_NODE_MINING_MODE = mode;
      env.KNOX_NODE_MINING_BACKEND = backend;
      env.KNOX_NODE_MINING_CPU_UTIL = String(cpuUtil);
      env.KNOX_NODE_MINING_GPU_UTIL = String(gpuUtil);
      env.KNOX_NODE_GPU_DEVICE_ID = String(gpuDeviceId);
      env.KNOX_NODE_CUDA_DEVICE_ORDINAL = String(cudaDeviceOrdinal);
      // When user explicitly selects a GPU backend, force-enable detection so the
      // Rust node doesn't fall back to CPU due to DLL path misses on modern drivers.
      if (backend === 'cuda') {
        env.KNOX_FORCE_CUDA_AVAILABLE = '1';
      } else if (backend === 'opencl') {
        env.KNOX_FORCE_OPENCL_AVAILABLE = '1';
      } else if (backend === 'auto') {
        // Auto: enable whichever the electron-side detector found.
        const detected = detectMiningBackends();
        if (detected.availableBackends.includes('cuda')) env.KNOX_FORCE_CUDA_AVAILABLE = '1';
        if (detected.availableBackends.includes('opencl')) env.KNOX_FORCE_OPENCL_AVAILABLE = '1';
      }
      // Difficulty, seq steps, and memory overrides are locked on mainnet.
      env.KNOX_NODE_MINING_DIFFICULTY_BITS = String(diff);
      env.KNOX_NODE_MINING_SEQ_STEPS = String(seq);
      env.KNOX_NODE_MINING_MEMORY_BYTES = String(mem);
      env.KNOX_LATTICE_DEBUG_DIFFICULTY_BITS = String(diff);
      env.KNOX_LATTICE_DEBUG_SEQ_STEPS = String(seq);
      env.KNOX_LATTICE_DEBUG_MEMORY_BYTES = String(mem);
    }
  }
  // Always emit a full backtrace on node crash so allocation failures are traceable.
  env.RUST_BACKTRACE = 'full';
  // Debug session: write sync logs to workspace when running from project, else userData.
  const cwd = process.cwd();
  const workspaceRoot = path.resolve(cwd, '..', '..', '..', '..');
  const inProject = require('fs').existsSync(path.join(workspaceRoot, 'Cargo.toml'));
  env.KNOX_DEBUG_LOG_PATH = inProject
    ? path.join(workspaceRoot, 'debug-dbd02b.log')
    : path.join(USER_DIR, 'debug-dbd02b.log');
  return env;
}

function resolveDifficultyBits(profile = null) {
  const fromProfile = Number(profile?.difficultyBits);
  if (Number.isFinite(fromProfile)) return clampInt(fromProfile, 1, 20, 6);
  const fromEnv = Number(process.env.KNOX_LATTICE_DEBUG_DIFFICULTY_BITS);
  if (Number.isFinite(fromEnv)) return clampInt(fromEnv, 1, 20, 6);
  return 6;
}

function primeRuntimeNodeForStart(profile = null) {
  runtimeStats.node.currentDifficultyBits = resolveDifficultyBits(profile);
  resetRuntimeMiningSession();
  runtimeStats.node.lastProposeHeight = null;
  runtimeStats.node.lastProposeRound = null;
  runtimeStats.node.lastProposeAtMs = 0;
  runtimeStats.node.lastReject = '';
  runtimeStats.node.miningMode = String(profile?.mode || 'hybrid').toLowerCase();
  runtimeStats.node.configuredBackend = String(profile?.backend || 'auto').toLowerCase();
  runtimeStats.node.activeBackend = 'cpu';
  runtimeStats.node.availableBackends = detectMiningBackends().availableBackends;
  runtimeStats.node.activeDevice = 'cpu-main';
  runtimeStats.node.fallbackActive = false;
  runtimeStats.node.lastBackendError = '';
  autoLedgerResetState.firstAtMs = 0;
  autoLedgerResetState.lastAtMs = 0;
  autoLedgerResetState.hitCount = 0;
}

async function resolveMinerAddress(options = {}) {
  const requireWalletAddress = !!options.requireWalletAddress;
  // Full lattice address: knox1 + 64 (view) + 64 (spend) + 4096 (lattice pub) = 4229 chars
  const FULL_LATTICE_ADDR_LEN = 5 + 64 + 64 + 4096;

  const isFullLatticeAddr = (addr) => {
    if (!addr || !addr.startsWith('knox1')) return false;
    return addr.length === FULL_LATTICE_ADDR_LEN && /^knox1[a-f0-9]+$/i.test(addr);
  };

  const explicit = String(process.env.KNOX_DESKTOP_MINER_ADDRESS || '').trim();
  if (explicit) {
    const mExplicit = explicit.match(/knox1[a-f0-9]{32,}/i);
    if (mExplicit) {
      if (isFullLatticeAddr(mExplicit[0])) return { ok: true, result: mExplicit[0] };
      if (requireWalletAddress) {
        return { ok: false, error: 'KNOX_DESKTOP_MINER_ADDRESS must be a full wallet address for mining' };
      }
      // Legacy short address – let node derive from key
      return { ok: true, result: '__derive__' };
    }
    return { ok: false, error: 'KNOX_DESKTOP_MINER_ADDRESS is set but invalid' };
  }

  const configured = String(desktopMinerAddress || '').trim();
  if (configured) {
    const mConfigured = configured.match(/knox1[a-f0-9]{32,}/i);
    if (mConfigured) {
      if (isFullLatticeAddr(mConfigured[0])) return { ok: true, result: mConfigured[0] };
      if (requireWalletAddress) {
        return { ok: false, error: 'saved miner address is not a full wallet address' };
      }
      // If it's at least 128 chars (view+spend), we'll try it, but warn
      if (mConfigured[0].length >= 133) {
        appendLog(null, `[mining] Using short/incomplete address: ${mConfigured[0].slice(0, 20)}...`);
        return { ok: true, result: mConfigured[0] };
      }
      return { ok: true, result: '__derive__' };
    }
  }

  if (service.walletd) {
    const info = await walletdCall('/info', null, { timeoutMs: 12000 });
    if (info.ok && info.result?.address) {
      const fromInfo = String(info.result.address).trim();
      if (isFullLatticeAddr(fromInfo)) return { ok: true, result: fromInfo };
      if (requireWalletAddress) {
        return { ok: false, error: 'wallet daemon returned a non-full address; cannot start mining safely' };
      }
    }
  }

  const addr = await runCli(['address', WALLET_PATH], { timeoutMs: 5000 });
  if (addr.ok) {
    const m = String(addr.result).match(/knox1[a-f0-9]{32,}/i);
    if (m) {
      if (isFullLatticeAddr(m[0])) return { ok: true, result: m[0] };
      if (requireWalletAddress) {
        return { ok: false, error: 'wallet address is not full-length; mining would not credit this wallet reliably' };
      }
      if (m[0].length >= 133) return { ok: true, result: m[0] };
      return { ok: true, result: '__derive__' };
    }
  }

  const allowPremineFallback = /^(1|true|yes)$/i.test(String(process.env.KNOX_DESKTOP_USE_PREMINE_AS_MINER || '0'));
  if (allowPremineFallback) {
    const premine = String(process.env.KNOX_MAINNET_PREMINE_ADDRESS || '').trim();
    const mPremine = premine.match(/knox1[a-f0-9]{32,}/i);
    if (mPremine) {
      if (isFullLatticeAddr(mPremine[0])) return { ok: true, result: mPremine[0] };
      return { ok: true, result: '__derive__' };
    }
  }

  if (requireWalletAddress) {
    return { ok: false, error: 'no wallet mining address found; create/import wallet first' };
  }

  // No address found at all; let node derive from its key
  return { ok: true, result: '__derive__' };
}

function nodeArgs(validatorsPath, minerAddr) {
  const args = [NODE_DATA_DIR, LOCAL_NODE_P2P, LOCAL_NODE_RPC, defaultPeerList(), validatorsPath];
  if (minerAddr && minerAddr !== '__derive__') args.push(minerAddr);
  return args;
}

function waitMs(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function noteMissingParentReject(height) {
  const now = Date.now();
  if (!autoLedgerResetState.firstAtMs || now - autoLedgerResetState.firstAtMs > 120000) {
    autoLedgerResetState.firstAtMs = now;
    autoLedgerResetState.hitCount = 0;
  }
  autoLedgerResetState.lastAtMs = now;
  autoLedgerResetState.hitCount += 1;
  return autoLedgerResetState.hitCount;
}

function shouldAutoResetLedgerFromReject(height) {
  if (!AUTO_LEDGER_RESET_ENABLED || autoLedgerResetInFlight) return false;
  if (Date.now() < autoLedgerResetCooldownUntilMs) return false;
  const localHeight = Number(runtimeStats.node.lastSealedHeight || 0);
  const rejectHeight = Number(height || 0);
  if (!Number.isFinite(localHeight) || !Number.isFinite(rejectHeight)) return false;
  // Trigger only on clear stale-ledger symptoms: high local tip + repeated low-height parent misses.
  if (localHeight < 128 || rejectHeight > 24) return false;
  const hits = noteMissingParentReject(rejectHeight);
  return hits >= 5;
}

async function resetLocalLedgerAndRestart(win, reason = 'auto-ledger-reset') {
  if (autoLedgerResetInFlight) return { ok: false, error: 'auto ledger reset already running' };
  autoLedgerResetInFlight = true;
  autoLedgerResetCooldownUntilMs = Date.now() + 5 * 60 * 1000;
  try {
    const profile = miningProfileState || loadMiningConfig().profile;
    const mine = nodeMineEnabled;
    const minerAddress = await resolveMinerAddress({ requireWalletAddress: !!mine });
    if (!minerAddress.ok) return minerAddress;

    appendLog(win, `[repair] detected stale local ledger (${reason}); rebuilding local node chain cache`);
    stopSvc('walletd');
    stopSvc('node');
    await waitMs(350);

    const ledgerPath = path.join(NODE_DATA_DIR, 'ledger');
    try {
      fs.rmSync(ledgerPath, { recursive: true, force: true });
      appendLog(win, `[repair] removed local ledger: ${ledgerPath}`);
    } catch (err) {
      return { ok: false, error: `failed to remove local ledger: ${String(err?.message || err)}` };
    }

    const validatorsPath = ensureValidatorsFile(win);
    const nodeBin = resolveBin('knox-node.exe');
    primeRuntimeNodeForStart(profile);
    const nodeStart = spawnSvc(
      win,
      'node',
      nodeBin,
      nodeArgs(validatorsPath, minerAddress.result),
      nodeDesktopEnv(mine, profile, lastUpstreamTipSeen, minerAddress.result)
    );
    if (!nodeStart.ok) return nodeStart;

    const walletStart = startWalletdOnRpc(win, walletdRpcAddr());
    if (!walletStart.ok) return walletStart;
    if (USE_LOCAL_RPC_WHEN_NODE_RUNNING && service.node && walletdRpcTarget !== LOCAL_NODE_RPC) {
      stopSvc('walletd');
      await waitMs(250);
      const moved = startWalletdOnRpc(win, LOCAL_NODE_RPC);
      if (!moved.ok) return moved;
    }
    queueWalletAutoSync(win, 'auto-ledger-reset');
    autoLedgerResetState.firstAtMs = 0;
    autoLedgerResetState.lastAtMs = 0;
    autoLedgerResetState.hitCount = 0;
    appendLog(win, '[repair] local ledger reset complete');
    return { ok: true, result: 'local ledger reset complete' };
  } finally {
    autoLedgerResetInFlight = false;
  }
}

function parseKnoxAddress(value) {
  const m = String(value || '').trim().match(/knox1[a-f0-9]{32,}/i);
  return m ? m[0] : '';
}

function isTimeoutErrorText(text) {
  return /timeout|timed out|ETIMEDOUT|request timeout/i.test(String(text || ''));
}

function isConnRefusedErrorText(text) {
  return /(ECONNREFUSED|Connection refused|os error 10061|actively refused)/i.test(
    String(text || '')
  );
}

const WALLET_CLI_RPC_ENV = {
  KNOX_RPC_CONNECT_TIMEOUT_MS: '15000',
  KNOX_RPC_IO_TIMEOUT_MS: '120000'
};
const WALLET_CLI_SYNC_TIMEOUT_MS = 5 * 60 * 1000;

async function fallbackCliSyncAndReloadWalletd(win, reason = 'fallback') {
  backupWalletSnapshot(win || mainWindow, `sync-${reason}`, { minIntervalMs: 10 * 60 * 1000 });
  const rpcAddr = walletSyncRpcAddr();
  appendLog(win || mainWindow, `[wallet] fallback sync via CLI on ${rpcAddr} (${reason})`);
  const cli = await runCli(['sync', WALLET_PATH, rpcAddr], {
    timeoutMs: WALLET_CLI_SYNC_TIMEOUT_MS,
    env: WALLET_CLI_RPC_ENV
  });
  if (!cli.ok) {
    appendLog(win || mainWindow, `[wallet] fallback CLI sync failed: ${cli.error || 'unknown'}`);
    return cli;
  }
  runtimeStats.walletd.lastInfoAtMs = Date.now();
  runtimeStats.walletd.lastInfoError = '';
  runtimeStats.walletd.lastSyncError = '';
  if (service.walletd) {
    const target = walletdRpcAddr();
    stopSvc('walletd');
    await waitMs(250);
    const restarted = startWalletdOnRpc(win || mainWindow, target);
    if (!restarted.ok) {
      appendLog(win || mainWindow, `[wallet] wallet daemon restart after fallback sync failed: ${restarted.error || 'unknown'}`);
      return restarted;
    }
  }
  emitWalletUpdated(win || mainWindow, `fallback-cli-sync:${reason}`);
  return { ok: true, result: 'fallback sync complete' };
}

async function walletRescanAndReloadWalletd(win, reason = 'manual-rescan') {
  const backup = backupWalletSnapshot(win || mainWindow, `rescan-${reason}`, { minIntervalMs: 5 * 60 * 1000 });
  if (!backup.ok) return backup;
  const rpcAddr = walletSyncRpcAddr();
  const hadWalletd = !!service.walletd;
  const walletTarget = walletdRpcTarget || walletdRpcAddr();

  appendLog(win || mainWindow, `[wallet] rescan via CLI on ${rpcAddr} (${reason})`);
  if (hadWalletd) {
    stopSvc('walletd');
    await waitMs(250);
  }

  const cli = await runCli(['rescan', WALLET_PATH, rpcAddr], {
    timeoutMs: WALLET_CLI_SYNC_TIMEOUT_MS,
    env: WALLET_CLI_RPC_ENV
  });

  let restartError = '';
  if (hadWalletd) {
    const restarted = startWalletdOnRpc(win || mainWindow, walletTarget);
    if (!restarted.ok) {
      restartError = String(restarted.error || 'unknown');
      appendLog(win || mainWindow, `[wallet] wallet daemon restart after rescan failed: ${restartError}`);
    } else {
      queueWalletAutoSync(win || mainWindow, 'wallet-rescan');
    }
  }

  if (!cli.ok) {
    const msg = String(cli.error || 'wallet rescan failed');
    return { ok: false, error: restartError ? `${msg}; walletd restart failed: ${restartError}` : msg };
  }

  runtimeStats.walletd.lastInfoAtMs = Date.now();
  runtimeStats.walletd.lastInfoError = '';
  runtimeStats.walletd.lastSyncError = '';
  emitWalletUpdated(win || mainWindow, `rescan:${reason}`);

  if (restartError) {
    return { ok: false, error: `wallet rescan completed but walletd restart failed: ${restartError}` };
  }
  return { ok: true, result: 'wallet rescan complete' };
}

function failedServiceStart(name) {
  const info = lastExit[name];
  if (!info) return `${name} failed to stay alive after start`;
  if (info.hint) return `${name} failed: ${info.hint}`;
  return `${name} failed: code=${info.code} signal=${info.signal}`;
}

async function forceMiningOffForSafety(win, reason = 'upstream connectivity lost') {
  if (!service.node || !nodeMineEnabled) return { ok: true, result: 'mining already off' };
  appendLog(win, `[safety] ${reason}; forcing mining OFF to prevent local forking`);
  const validatorsPath = ensureValidatorsFile(win);
  const nodeBin = resolveBin('knox-node.exe');
  const minerAddress = await resolveMinerAddress();
  if (!minerAddress.ok) return minerAddress;
  const effectiveProfile = miningProfileState || loadMiningConfig().profile;
  stopSvc('node');
  await waitMs(500);
  primeRuntimeNodeForStart(effectiveProfile);
  const restarted = spawnSvc(
    win,
    'node',
    nodeBin,
    nodeArgs(validatorsPath, minerAddress.result),
    nodeDesktopEnv(false, effectiveProfile, 0, minerAddress.result)
  );
  if (restarted.ok) {
    nodeMineEnabled = false;
    miningSafetyTripped = true;
    appendLog(win, '[safety] node restarted with mining OFF');
  }
  return restarted;
}

async function quickStart(win, profile = null) {
  if (quickStartBusy) return { ok: false, error: 'quick start already running' };
  quickStartBusy = true;
  try {
    // Forced remote mode: do not start a local node; keep GUI height bound to upstream VM chain.
    if (FORCE_REMOTE_WALLET_MODE) {
      ensureDirs();
      const tls = ensureTls();
      if (!tls.ok) return tls;
      const walletEnsure = await ensureWalletExists();
      if (!walletEnsure.ok) return walletEnsure;
      if (service.node) {
        appendLog(win, '[startup] remote-rpc mode active; stopping local node');
        stopSvc('node');
        await waitMs(250);
      }
      const walletStart = await ensureWalletdUpstreamConnected(win, UPSTREAM_PROBE_TIMEOUT_MS);
      if (!walletStart.ok) return walletStart;
      await waitMs(800);
      if (!service.walletd) return { ok: false, error: failedServiceStart('walletd') };
      queueWalletAutoSync(win, 'quick-start-remote-rpc');
      appendLog(win, `[startup] remote-rpc mode active; walletd bound to ${walletdRpcTarget || RPC_UPSTREAM}`);
      return { ok: true, result: 'quick start complete (remote-rpc mode)' };
    }

    ensureDirs();
    const validatorsPath = ensureValidatorsFile(win);
    const tls = ensureTls();
    if (!tls.ok) return tls;

    const walletEnsure = await ensureWalletExists();
    if (!walletEnsure.ok) return walletEnsure;

    let allowMiningBoot = true;
    const walletStart = await ensureWalletdUpstreamConnected(win, UPSTREAM_PROBE_TIMEOUT_MS);
    if (!walletStart.ok) {
      if (!ALLOW_DEGRADED_UPSTREAM_BOOT) return walletStart;
      allowMiningBoot = false;
      appendLog(
        win,
        `[startup] upstream RPC probe unavailable; node will start with mining OFF (${walletStart.error || 'unknown'})`
      );
    }

    // Launch gate: do not mine until we can see remote chain tip.
    const tipReady = await waitForRemoteTipVisible(win, 0, 25000);
    let minLocalHeightForMining = 0;
    if (!tipReady.ok) {
      if (!ALLOW_DEGRADED_UPSTREAM_BOOT) return tipReady;
      allowMiningBoot = false;
      appendLog(
        win,
        `[startup] remote tip gate timed out; node will start with mining OFF (${tipReady.error || 'unknown'})`
      );
    } else {
      minLocalHeightForMining = Math.max(0, Number(tipReady.result) || 0);
    }

    const minerAddress = await resolveMinerAddress({ requireWalletAddress: !!allowMiningBoot });
    if (!minerAddress.ok) return minerAddress;

    const nodeBin = resolveBin('knox-node.exe');
    const effectiveProfile = profile || miningProfileState || loadMiningConfig().profile;
    primeRuntimeNodeForStart(effectiveProfile);
    const nodeStart = spawnSvc(
      win,
      'node',
      nodeBin,
      nodeArgs(validatorsPath, minerAddress.result),
      nodeDesktopEnv(allowMiningBoot, effectiveProfile, minLocalHeightForMining, minerAddress.result)
    );
    appendLog(win, `[node] spawning with miner_address=${minerAddress.result === '__derive__' ? '(derived from node key)' : safeShortAddress(minerAddress.result)}`);
    nodeMineEnabled = !!allowMiningBoot;
    miningProfileState = effectiveProfile;
    if (!nodeStart.ok) return nodeStart;
    appendLog(
      win,
      `[config] node mining=${allowMiningBoot ? 'on' : 'off'} mode=${effectiveProfile?.mode || 'hybrid'} backend=${effectiveProfile?.backend || 'auto'} peers="${defaultPeerList() || '<none>'}" validators_mode=${USE_VALIDATORS_FILE_FOR_DESKTOP_NODE ? 'file' : 'local-solo'} diff=${effectiveProfile?.difficultyBits ?? 'auto'} seq=${effectiveProfile?.seqSteps ?? 'auto'} mem=${effectiveProfile?.memoryBytes ?? 'auto'} cpu_util=${effectiveProfile?.cpuUtil ?? 'auto'} gpu_util=${effectiveProfile?.gpuUtil ?? 'auto'} upstream_batch=${process.env.KNOX_NODE_UPSTREAM_SYNC_BATCH_COUNT} upstream_timeout_ms=${process.env.KNOX_NODE_UPSTREAM_SYNC_TIMEOUT_MS}`
    );
    if (USE_LOCAL_RPC_WHEN_NODE_RUNNING && service.node && walletdRpcTarget !== LOCAL_NODE_RPC) {
      appendLog(win, `[sync] moving wallet daemon to local RPC: ${LOCAL_NODE_RPC}`);
      stopSvc('walletd');
      await waitMs(250);
      const moved = startWalletdOnRpc(win, LOCAL_NODE_RPC);
      if (!moved.ok) return moved;
    }

    await waitMs(1600);
    if (!service.node) return { ok: false, error: failedServiceStart('node') };
    if (!service.walletd) return { ok: false, error: failedServiceStart('walletd') };
    queueWalletAutoSync(win, 'quick-start');

    return { ok: true, result: 'quick start complete' };
  } finally {
    quickStartBusy = false;
  }
}

function serviceState() {
  return {
    ok: true,
    result: {
      nodeRunning: !!service.node,
      walletdRunning: !!service.walletd,
      rpcAddress: walletdRpcAddr(),
      rpcUpstream: RPC_UPSTREAM,
      walletdRpcTarget,
      localRpcAddress: LOCAL_NODE_RPC,
      walletdBind: WALLETD_BIND,
      walletPath: WALLET_PATH,
      miningConfigPath: MINING_CFG_PATH,
      miningEnabled: nodeMineEnabled,
      miningProfile: miningProfileState,
      miningBackends: detectMiningBackends(),
      configuredBackend: runtimeStats.node.configuredBackend,
      activeBackend: runtimeStats.node.activeBackend,
      activeDevice: runtimeStats.node.activeDevice,
      backendFallback: runtimeStats.node.fallbackActive,
      backendError: runtimeStats.node.lastBackendError,
      selectedMinerAddress: desktopMinerAddress || '',
      nodeLastExit: lastExit.node,
      walletdLastExit: lastExit.walletd,
      runtime: runtimeStats
    }
  };
}

function computeChainHardening(tip) {
  const BLOCKS_PER_YEAR = 701560;
  const ANNUAL_ESCALATION = 0.08;
  let total = 0;
  for (let h = 0; h <= tip; h++) {
    const year = h / BLOCKS_PER_YEAR;
    const bits = Math.round(12.0 * Math.pow(1.0 + ANNUAL_ESCALATION, year));
    total += Math.min(28, Math.max(10, bits));
  }
  return total;
}

function runtimeNetworkSnapshot() {
  const n = runtimeStats.node;
  const tip = Number.isFinite(Number(n.lastSealedHeight)) ? Number(n.lastSealedHeight) : 0;
  const minerCount = n.running
    ? (String(n.miningMode || 'hybrid') === 'hybrid' && String(n.activeBackend || 'cpu') !== 'cpu' ? 2 : 1)
    : 0;
  return {
    tip_height: tip,
    total_hardening: computeChainHardening(tip),
    active_miners_recent: minerCount,
    software_version: DESKTOP_APP_VERSION,
    latest_installer_version: MIN_SUPPORTED_INSTALLER_VERSION,
    min_supported_version: MIN_SUPPORTED_INSTALLER_VERSION,
    min_supported_protocol_version: MIN_SUPPORTED_P2P_PROTOCOL_VERSION,
    current_difficulty_bits: Number(n.currentDifficultyBits || 0),
    tip_proposer_streak: Number(n.currentStreak || 0),
    next_streak_if_same_proposer: Math.max(0, Number(n.currentStreak || 0) + 1),
    streak_bonus_ppm: 0,
    surge_phase: 'idle',
    surge_countdown_ms: 0,
    surge_block_index: 0,
    surge_blocks_remaining: 0,
    recent_blocks: (n.recentBlocks || []).map((b) => ({
      height: Number(b.height || 0),
      time: Number(b.atMs || n.lastSealedAtMs || Date.now()),
      txs: Number(b.txs || 0),
      status: b.status || 'SEALED',
      meta: `${Number(b.txs || 0)} tx`
    }))
  };
}

function networkTelemetryBaseSnapshot() {
  if (lastGoodNetworkTelemetry && typeof lastGoodNetworkTelemetry === 'object') {
    return {
      ...lastGoodNetworkTelemetry,
      software_version: DESKTOP_APP_VERSION,
      latest_installer_version: MIN_SUPPORTED_INSTALLER_VERSION,
      min_supported_version: MIN_SUPPORTED_INSTALLER_VERSION,
      min_supported_protocol_version: MIN_SUPPORTED_P2P_PROTOCOL_VERSION,
      recent_blocks: Array.isArray(lastGoodNetworkTelemetry.recent_blocks)
        ? [...lastGoodNetworkTelemetry.recent_blocks]
        : []
    };
  }
  return runtimeNetworkSnapshot();
}

function pinnedLocalNetworkTelemetry() {
  if (!service.node || !lastGoodNetworkTelemetry) return null;
  const local = runtimeNetworkSnapshot();
  const localTip = Number(local.tip_height || 0);
  const cachedTip = Number(lastGoodNetworkTelemetry.tip_height || 0);
  if (localTip <= 0 || lastUpstreamTipSeen <= 0) return null;
  if (localTip + UPSTREAM_TIP_REGRESSION_TOLERANCE < lastUpstreamTipSeen) return null;
  const mergedTip = Math.max(localTip, cachedTip, lastUpstreamTipSeen);
  return {
    ...lastGoodNetworkTelemetry,
    tip_height: mergedTip,
    total_hardening: computeChainHardening(mergedTip),
    current_difficulty_bits: Math.max(
      Number(lastGoodNetworkTelemetry.current_difficulty_bits || 0),
      Number(local.current_difficulty_bits || 0)
    ),
    tip_proposer_streak: Math.max(
      Number(lastGoodNetworkTelemetry.tip_proposer_streak || 0),
      Number(local.tip_proposer_streak || 0)
    ),
    next_streak_if_same_proposer: Math.max(
      Number(lastGoodNetworkTelemetry.next_streak_if_same_proposer || 0),
      Number(local.next_streak_if_same_proposer || 0)
    ),
    recent_blocks: local.recent_blocks && local.recent_blocks.length > 0
      ? local.recent_blocks
      : (lastGoodNetworkTelemetry.recent_blocks || []),
    source: 'local-node-pinned'
  };
}

function onboardingState() {
  return {
    ok: true,
    result: {
      nodeBinaryReady: fs.existsSync(resolveBin('knox-node.exe')),
      nodePath: resolveBin('knox-node.exe'),
      walletBinaryReady: fs.existsSync(resolveBin('knox-wallet.exe')),
      walletPath: resolveBin('knox-wallet.exe'),
      walletCliBinaryReady: fs.existsSync(resolveBin('knox-wallet-cli.exe')),
      walletCliPath: resolveBin('knox-wallet-cli.exe'),
      miningConfigReady: fs.existsSync(MINING_CFG_PATH),
      miningConfigPath: MINING_CFG_PATH,
      tlsCertReady: fs.existsSync(CERT_PATH),
      tlsKeyReady: fs.existsSync(KEY_PATH),
      walletFileReady: fs.existsSync(WALLET_PATH)
    }
  };
}

function bindIpc(channel, label, handler) {
  ipcMain.removeHandler(channel);
  ipcMain.handle(channel, async (...args) => {
    const noisy =
      label === 'service-state' ||
      label === 'onboarding-state' ||
      label === 'walletd-info' ||
      label === 'walletd-health' ||
      label === 'walletd-addresses' ||
      label === 'walletd-network' ||
      label === 'walletd-fib-wall' ||
      label === 'mining-backends' ||
      label === 'mining-runtime' ||
      label === 'node-runtime-stats';
    if (!noisy) appendLog(mainWindow, `[ipc] ${label} called`);
    try {
      const out = await handler(...args);
      if (out && Object.prototype.hasOwnProperty.call(out, 'ok')) {
        if (!noisy && out.ok && label === 'service-state' && out.result) {
          appendLog(
            mainWindow,
            `[ipc] ${label} -> ok (node=${out.result.nodeRunning ? 'up' : 'down'}, walletd=${out.result.walletdRunning ? 'up' : 'down'}, rpc=${out.result.walletdRpcTarget || out.result.rpcAddress})`
          );
        } else if (!noisy && out.ok && label === 'walletd-network' && out.result) {
          appendLog(
            mainWindow,
            `[ipc] ${label} -> ok (height=${out.result.tip_height ?? out.result.height ?? '?'}, diff=${out.result.current_difficulty_bits ?? out.result.difficulty_bits ?? '?'})`
          );
        } else if (!noisy) {
          appendLog(mainWindow, `[ipc] ${label} -> ${out.ok ? 'ok' : `error: ${out.error || 'unknown'}`}`);
        }
      } else {
        if (!noisy) appendLog(mainWindow, `[ipc] ${label} -> ok`);
      }
      return out;
    } catch (err) {
      const msg = String(err?.stack || err);
      appendLog(mainWindow, `[ipc] ${label} threw: ${msg}`);
      return { ok: false, error: msg };
    }
  });
}

function createWindow() {
  const win = new BrowserWindow({
    width: 1720,
    height: 1040,
    minWidth: 1400,
    minHeight: 860,
    backgroundColor: '#040816',
    autoHideMenuBar: false,
    webPreferences: {
      preload: path.join(ROOT, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  Menu.setApplicationMenu(Menu.getApplicationMenu());
  win.loadFile(path.join(ROOT, 'renderer', 'index.html'));
  win.webContents.on('context-menu', (_event, params) => {
    const menu = Menu.buildFromTemplate([
      { role: 'undo', enabled: params.editFlags.canUndo },
      { role: 'redo', enabled: params.editFlags.canRedo },
      { type: 'separator' },
      { role: 'cut', enabled: params.editFlags.canCut },
      { role: 'copy', enabled: params.editFlags.canCopy },
      { role: 'paste', enabled: params.editFlags.canPaste },
      { role: 'selectAll' }
    ]);
    menu.popup({ window: win });
  });

  mainWindow = win;
  win.on('closed', () => {
    if (mainWindow === win) mainWindow = null;
  });

  bindIpc('quick-start', 'quick-start', (_e, profile = null) => quickStart(win, profile));
  bindIpc('start-node', 'start-node', async (_e, mine = true, profile = null) => {
    if (FORCE_REMOTE_WALLET_MODE) {
      return { ok: false, error: 'local node is disabled in mainnet remote mode' };
    }
    if (service.node) {
      nodeMineEnabled = !!mine;
      miningProfileState = profile || miningProfileState || loadMiningConfig().profile;
      return {
        ok: true,
        result: 'node already running; use Apply Changes to reconfigure live'
      };
    }
    const validatorsPath = ensureValidatorsFile(win);
    let requestedMine = !!mine;
    let minLocalHeightForMining = 0;
    if (requestedMine) {
      if (!service.walletd) {
        const walletStart = await ensureWalletdUpstreamConnected(win, UPSTREAM_PROBE_TIMEOUT_MS);
        if (!walletStart.ok) {
          if (!ALLOW_DEGRADED_UPSTREAM_BOOT) return walletStart;
          requestedMine = false;
          appendLog(
            win,
            `[startup] walletd upstream probe unavailable; forcing mining OFF (${walletStart.error || 'unknown'})`
          );
        }
        await waitMs(500);
      }
      const tipReady = await waitForRemoteTipVisible(win, 0, 25000);
      if (!tipReady.ok) {
        if (!ALLOW_DEGRADED_UPSTREAM_BOOT) return tipReady;
        requestedMine = false;
        appendLog(
          win,
          `[startup] remote tip gate timed out; forcing mining OFF (${tipReady.error || 'unknown'})`
        );
      } else {
        minLocalHeightForMining = Math.max(0, Number(tipReady.result) || 0);
      }
    }
    const nodeBin = resolveBin('knox-node.exe');
    const minerAddress = await resolveMinerAddress({ requireWalletAddress: !!requestedMine });
    if (!minerAddress.ok) return minerAddress;
    const effectiveProfile = profile || miningProfileState || loadMiningConfig().profile;
    primeRuntimeNodeForStart(effectiveProfile);
    const started = spawnSvc(
      win,
      'node',
      nodeBin,
      nodeArgs(validatorsPath, minerAddress.result),
      nodeDesktopEnv(requestedMine, effectiveProfile, minLocalHeightForMining, minerAddress.result)
    );
    if (!started.ok) return started;
    nodeMineEnabled = !!requestedMine;
    miningProfileState = effectiveProfile;
    appendLog(
      win,
      `[config] node mining=${requestedMine ? 'on' : 'off'} mode=${effectiveProfile?.mode || 'hybrid'} backend=${effectiveProfile?.backend || 'auto'} peers="${defaultPeerList() || '<none>'}" validators_mode=${USE_VALIDATORS_FILE_FOR_DESKTOP_NODE ? 'file' : 'local-solo'} diff=${effectiveProfile?.difficultyBits ?? 'auto'} seq=${effectiveProfile?.seqSteps ?? 'auto'} mem=${effectiveProfile?.memoryBytes ?? 'auto'} cpu_util=${effectiveProfile?.cpuUtil ?? 'auto'} gpu_util=${effectiveProfile?.gpuUtil ?? 'auto'} upstream_batch=${env.KNOX_NODE_UPSTREAM_SYNC_BATCH_COUNT} upstream_timeout_ms=${env.KNOX_NODE_UPSTREAM_SYNC_TIMEOUT_MS}`
    );

    if (USE_LOCAL_RPC_WHEN_NODE_RUNNING && service.walletd && walletdRpcTarget !== LOCAL_NODE_RPC) {
      appendLog(win, `[sync] switching wallet daemon RPC to local: ${LOCAL_NODE_RPC}`);
      stopSvc('walletd');
      const restarted = startWalletdOnRpc(win, LOCAL_NODE_RPC);
      if (!restarted.ok) return restarted;
      return { ok: true, result: 'node started; wallet daemon moved to local RPC' };
    }
    return started;
  });
  bindIpc('start-walletd', 'start-walletd', async () => {
    const walletEnsure = await ensureWalletExists();
    if (!walletEnsure.ok) return walletEnsure;
    const tls = ensureTls();
    if (!tls.ok) return tls;
    const started = await ensureWalletdUpstreamConnected(win, UPSTREAM_PROBE_TIMEOUT_MS);
    if (started.ok) queueWalletAutoSync(win, 'walletd-start');
    return started;
  });
  bindIpc('stop-service', 'stop-service', (_e, name) => stopSvc(name));
  bindIpc('service-state', 'service-state', () => serviceState());
  bindIpc('onboarding-state', 'onboarding-state', () => onboardingState());
  bindIpc('node-runtime-stats', 'node-runtime-stats', () => ({ ok: true, result: runtimeStats }));

  bindIpc('wallet-create', 'wallet-create', async (_e, force = false) => {
    const walletExists = fs.existsSync(WALLET_PATH);
    const walletSize = walletExists ? Number(fs.statSync(WALLET_PATH).size || 0) : 0;
    if (walletExists && walletSize > 0 && !force) {
      // Startup creates/imports a wallet automatically; treat create as idempotent unless force=true.
      return { ok: true, result: 'wallet already exists' };
    }
    const backup = backupWalletSnapshot(win, force ? 'wallet-create-force' : 'wallet-create');
    if (!backup.ok) return backup;
    const out = await runCli(['create', WALLET_PATH]);
    if (!out.ok) return out;
    if (service.walletd) {
      const target = walletdRpcTarget || walletdRpcAddr();
      stopSvc('walletd');
      await waitMs(250);
      const restart = startWalletdOnRpc(win, target);
      if (!restart.ok) return restart;
    }
    if (service.node) {
      stopSvc('node');
      await waitMs(300);
      const validatorsPath = ensureValidatorsFile(win);
      const nodeBin = resolveBin('knox-node.exe');
      const minerAddress = await resolveMinerAddress({ requireWalletAddress: !!nodeMineEnabled });
      if (!minerAddress.ok) return minerAddress;
      const effectiveProfile = miningProfileState || loadMiningConfig().profile;
      primeRuntimeNodeForStart(effectiveProfile);
      const restarted = spawnSvc(
        win,
        'node',
        nodeBin,
        nodeArgs(validatorsPath, minerAddress.result),
        nodeDesktopEnv(nodeMineEnabled, effectiveProfile, lastUpstreamTipSeen, minerAddress.result)
      );
      if (!restarted.ok) return restarted;
      appendLog(win, '[config] node restarted to apply new wallet mining address');
    }
    return out;
  });
  bindIpc('wallet-address', 'wallet-address', async () => {
    if (service.walletd) {
      const info = await walletdCall('/info');
      if (info.ok && info.result?.address) return { ok: true, result: info.result.address };
      return { ok: false, error: info.error || 'wallet daemon failed to provide address' };
    }
    return runCli(['address', WALLET_PATH]);
  });
  bindIpc('wallet-addresses', 'wallet-addresses', async () => {
    if (service.walletd) {
      const info = await walletdCall('/info');
      if (info.ok && info.result?.addresses?.length) {
        return { ok: true, result: String(info.result.addresses.join('\n')) };
      }
      return { ok: false, error: info.error || 'wallet daemon failed to provide addresses' };
    }
    return runCli(['addresses', WALLET_PATH]);
  });
  bindIpc('miner-address-get', 'miner-address-get', () => ({ ok: true, result: desktopMinerAddress || '' }));
  bindIpc('miner-address-set', 'miner-address-set', async (_e, addr) => {
    const parsed = parseKnoxAddress(addr);
    if (!parsed) return { ok: false, error: 'invalid KNOX address' };
    desktopMinerAddress = parsed;
    saveMiningConfig({ minerAddress: parsed });
    if (!service.node) {
      return { ok: true, result: `mining address saved: ${parsed}` };
    }
    stopSvc('node');
    await waitMs(300);
    const validatorsPath = ensureValidatorsFile(win);
    const nodeBin = resolveBin('knox-node.exe');
    const effectiveProfile = miningProfileState || loadMiningConfig().profile;
    primeRuntimeNodeForStart(effectiveProfile);
    const restarted = spawnSvc(
      win,
      'node',
      nodeBin,
      nodeArgs(validatorsPath, parsed),
      nodeDesktopEnv(nodeMineEnabled, effectiveProfile, lastUpstreamTipSeen, parsed)
    );
    if (!restarted.ok) return restarted;
    queueWalletAutoSync(win, 'miner-address-changed');
    return { ok: true, result: `mining address set and node restarted` };
  });
  bindIpc('wallet-new-address', 'wallet-new-address', async () => {
    const backup = backupWalletSnapshot(win, 'new-address', { minIntervalMs: 60 * 1000 });
    if (!backup.ok) return backup;
    if (service.walletd) {
      const out = await walletdCall('/new-address', {});
      if (out.ok) return out;
    }
    return runCli(['new-address', WALLET_PATH]);
  });
  bindIpc('wallet-balance', 'wallet-balance', async () => {
    if (service.walletd) {
      const info = await walletdCall('/info');
      if (info.ok) {
        return {
          ok: true,
          result: `Balance: ${Number(info.result?.balance || 0) / 1e8} KNOX (${Number(info.result?.balance || 0)})`
        };
      }
    }
    return runCli(['balance', WALLET_PATH]);
  });
  bindIpc('wallet-sync', 'wallet-sync', async () => {
    const backup = backupWalletSnapshot(win, 'manual-sync', { minIntervalMs: 3 * 60 * 1000 });
    if (!backup.ok) return backup;
    if (service.walletd) {
      const out = await walletdCall('/sync', {}, { timeoutMs: 25000 });
      runtimeStats.walletd.lastInfoAtMs = Date.now();
    if (out.ok) {
      runtimeStats.walletd.lastSyncError = '';
      runtimeStats.walletd.lastInfoError = '';
      emitWalletUpdated(win, 'manual-sync');
      return out;
    } else {
        runtimeStats.walletd.lastSyncError = String(out.error || 'sync failed');
        if (isTimeoutErrorText(out.error)) {
          return fallbackCliSyncAndReloadWalletd(win, 'manual-sync-timeout');
        }
      }
      return out;
    }
    return runCli(['sync', WALLET_PATH, walletSyncRpcAddr()], {
      timeoutMs: WALLET_CLI_SYNC_TIMEOUT_MS,
      env: WALLET_CLI_RPC_ENV
    });
  });
  bindIpc('wallet-rescan', 'wallet-rescan', async () => walletRescanAndReloadWalletd(win, 'manual-rescan'));

  bindIpc('walletd-health', 'walletd-health', () => walletdCall('/health'));
  bindIpc('walletd-info', 'walletd-info', async () => {
    const out = await walletdCall('/info');
    const balances = await walletBalancesFromCli();
    if (out.ok) {
      const merged = { ...(out.result || {}) };
      if (balances.ok) {
        if (Number.isFinite(Number(balances.result?.totalBalance))) {
          merged.balance = Number(balances.result.totalBalance);
        }
        merged.subaddressBalances = balances.result?.subaddressBalances || {};
        if (Array.isArray(balances.result?.addresses) && balances.result.addresses.length) {
          const mergedAddresses = new Set(
            []
              .concat(Array.isArray(merged.addresses) ? merged.addresses : [])
              .concat(balances.result.addresses.map((entry) => entry.address).filter(Boolean))
          );
          merged.addresses = Array.from(mergedAddresses);
          if (!merged.address && merged.addresses.length) merged.address = merged.addresses[0];
        }
      }
      trimPendingRewards(merged.last_height || merged.height || 0);
      const indexedEntries = Array.isArray(balances.result?.addresses) ? balances.result.addresses : [];
      const pending = pendingRewardsForAddresses(indexedEntries);
      merged.pendingBalance = pending.total;
      merged.pendingSubaddressBalances = pending.bySubaddress;
      return { ok: true, result: merged };
    }
    const fallback = await walletInfoFromCli();
    if (fallback?.ok) {
      const indexedEntries = Array.isArray(balances.result?.addresses) ? balances.result.addresses : [];
      const pending = pendingRewardsForAddresses(indexedEntries);
      fallback.result.pendingBalance = pending.total;
      fallback.result.pendingSubaddressBalances = pending.bySubaddress;
    }
    return fallback;
  });
  bindIpc('walletd-addresses', 'walletd-addresses', async () => {
    const out = await walletdCall('/addresses');
    if (out.ok) return out;
    return walletIndexedAddressesFromCli();
  });
  bindIpc('wallet-import-node-key', 'wallet-import-node-key', async (_e, nodeKeyPath = '') => {
    const normalizedPath = String(nodeKeyPath || '').trim();
    if (!normalizedPath) return { ok: false, error: 'node key path is required' };
    if (!service.walletd) {
      return { ok: false, error: 'wallet daemon must be running for import-node-key' };
    }
    const backup = backupWalletSnapshot(win, 'import-node-key');
    if (!backup.ok) return backup;
    const out = await walletdCall('/import-node-key', { node_key_path: normalizedPath }, { timeoutMs: 20000 });
    if (!out.ok) return out;
    runtimeStats.walletd.lastInfoAtMs = Date.now();
    runtimeStats.walletd.lastInfoError = '';
    runtimeStats.walletd.lastSyncError = '';
    queueWalletAutoSync(win, 'import-node-key');
    return out;
  });
  bindIpc('wallet-backups-list', 'wallet-backups-list', (_e, limit = 50) => ({ ok: true, result: listWalletBackups(limit) }));
  bindIpc('wallet-backup-restore-latest', 'wallet-backup-restore-latest', () => restoreWalletBackup(win, ''));
  bindIpc('wallet-backup-restore', 'wallet-backup-restore', (_e, backupPath = '') => restoreWalletBackup(win, backupPath));
  bindIpc('walletd-send', 'walletd-send', (_e, payload) => {
    const backup = backupWalletSnapshot(win, 'send', { minIntervalMs: 60 * 1000 });
    if (!backup.ok) return backup;
    return walletdCall('/send', payload || {});
  });
  bindIpc('walletd-network', 'walletd-network', async () => {
    // While the local node is running, keep the dashboard pinned to the
    // local chain view so flaky walletd telemetry cannot bounce the UI back
    // to stale remote heights/miner counts.
    if (service.node && Number(runtimeStats.node.lastSealedHeight || 0) > 0) {
      const pinned = pinnedLocalNetworkTelemetry();
      return { ok: true, result: pinned || runtimeNetworkSnapshot() };
    }
    // In explicit local-RPC mode, prefer runtime snapshot while mining.
    if (USE_LOCAL_RPC_WHEN_NODE_RUNNING && service.node) {
      return { ok: true, result: runtimeNetworkSnapshot() };
    }
    if (walletdSwitchPromise) {
      await walletdSwitchPromise;
    }
    let out = await walletdCall('/network', null, { timeoutMs: WALLETD_NETWORK_TIMEOUT_MS });
    if (!out.ok) {
      appendLog(win, `[network] walletd /network failed: ${out.error || 'unknown'}`);
      // /network can fail under load while upstream is still healthy; verify with a lightweight tip probe first.
      const tipProbeFast = await walletdCall('/upstream-tip', null, {
        timeoutMs: Math.min(6000, WALLETD_NETWORK_TIMEOUT_MS)
      });
      if (tipProbeFast.ok && tipProbeFast.result) {
        resetUpstreamFailureState();
        const tipHeight = Number(tipProbeFast.result.tip_height ?? 0);
        const snap = networkTelemetryBaseSnapshot();
        const mergedTip = Number.isFinite(tipHeight)
          ? Math.max(tipHeight, Number(snap.tip_height || 0))
          : Number(snap.tip_height || 0);
        if (Number.isFinite(mergedTip)) {
          lastUpstreamTipSeen = Math.max(lastUpstreamTipSeen, mergedTip);
        }
        appendLog(win, `[network] /network timed out but upstream tip is reachable (tip=${mergedTip})`);
        return {
          ok: true,
          result: {
            ...snap,
            tip_height: mergedTip,
            software_version: DESKTOP_APP_VERSION,
            latest_installer_version: MIN_SUPPORTED_INSTALLER_VERSION,
            min_supported_version: MIN_SUPPORTED_INSTALLER_VERSION,
            min_supported_protocol_version: MIN_SUPPORTED_P2P_PROTOCOL_VERSION,
            total_hardening: computeChainHardening(mergedTip),
            source: 'upstream-tip-fallback'
          }
        };
      }
      upstreamFailureStreak += 1;
      const now = Date.now();
      if (!upstreamFailureFirstAtMs) upstreamFailureFirstAtMs = now;
      if (upstreamFailureStreak >= UPSTREAM_FAILOVER_STREAK && now >= walletdFailoverCooldownUntilMs) {
        walletdFailoverCooldownUntilMs = now + WALLETD_FAILOVER_COOLDOWN_MS;
        if (!WALLETD_RUNTIME_FAILOVER_ENABLED) {
          if (!service.walletd) {
            appendLog(win, '[network] walletd is down; restarting on sticky RPC endpoint');
            const restarted = await ensureWalletdUpstreamConnected(win, UPSTREAM_PROBE_TIMEOUT_MS, {
              preferCurrent: true
            });
            if (restarted.ok) {
              appendLog(win, `[network] walletd upstream restored -> ${restarted.result}`);
              out = await walletdCall('/network', null, { timeoutMs: WALLETD_NETWORK_TIMEOUT_MS });
              if (out.ok) resetUpstreamFailureState();
            } else {
              appendLog(win, `[network] walletd restart on sticky endpoint failed: ${restarted.error || 'unknown'}`);
            }
          } else {
            appendLog(win, '[network] upstream unstable; sticky RPC mode enabled (rotation disabled)');
          }
        } else {
          const currentEp = normalizeRpcEndpoint(walletdRpcTarget || '', '');
          const allCandidates = rpcCandidateList();
          const alternateCandidates = allCandidates.filter((ep) => ep && ep !== currentEp);
          if (alternateCandidates.length === 0) {
            if (!service.walletd) {
              appendLog(win, '[network] walletd is down; restarting on sole configured RPC endpoint');
              const restarted = await ensureWalletdUpstreamConnected(win, UPSTREAM_PROBE_TIMEOUT_MS, {
                preferCurrent: true
              });
              if (restarted.ok) {
                appendLog(win, `[network] walletd upstream restored -> ${restarted.result}`);
                out = await walletdCall('/network', null, { timeoutMs: WALLETD_NETWORK_TIMEOUT_MS });
                if (out.ok) resetUpstreamFailureState();
              } else {
                appendLog(win, `[network] walletd restart on sole endpoint failed: ${restarted.error || 'unknown'}`);
              }
            } else {
              appendLog(
                win,
                '[network] upstream unstable; only one RPC endpoint configured, skipping walletd restart'
              );
            }
          } else {
            appendLog(win, '[network] upstream unstable; rotating walletd RPC endpoint');
            const switched = await ensureWalletdUpstreamConnected(win, UPSTREAM_PROBE_TIMEOUT_MS, {
              excludeCurrent: true
            });
            if (switched.ok) {
              appendLog(win, `[network] walletd upstream failover -> ${switched.result}`);
              out = await walletdCall('/network', null, { timeoutMs: WALLETD_NETWORK_TIMEOUT_MS });
              if (out.ok) resetUpstreamFailureState();
            } else {
              appendLog(win, `[network] walletd upstream failover failed: ${switched.error || 'unknown'}`);
            }
          }
        }
      }
      const sustainedFailureMs = upstreamFailureFirstAtMs > 0 ? (Date.now() - upstreamFailureFirstAtMs) : 0;
      if (
        UPSTREAM_MINING_SAFETY_AUTO_OFF
        && service.node
        && nodeMineEnabled
        && upstreamFailureStreak >= UPSTREAM_MINING_SAFETY_STREAK
        && sustainedFailureMs >= UPSTREAM_MINING_SAFETY_GRACE_MS
      ) {
        await forceMiningOffForSafety(
          win,
          `upstream RPC unhealthy (${upstreamFailureStreak} failures over ${Math.round(sustainedFailureMs / 1000)}s)`
        );
      } else if (
        service.node
        && nodeMineEnabled
        && !UPSTREAM_MINING_SAFETY_AUTO_OFF
        && upstreamFailureStreak >= UPSTREAM_MINING_SAFETY_STREAK
        && sustainedFailureMs >= UPSTREAM_MINING_SAFETY_GRACE_MS
      ) {
        const nowMs = Date.now();
        if (nowMs - upstreamSafetyDisabledNoticeAtMs > 30000) {
          upstreamSafetyDisabledNoticeAtMs = nowMs;
          appendLog(
            win,
            `[safety] upstream RPC unhealthy (${upstreamFailureStreak} failures over ${Math.round(sustainedFailureMs / 1000)}s); auto mining-off disabled`
          );
        }
      }
    } else {
      if (upstreamFailureStreak > 0) {
        appendLog(win, `[network] upstream RPC transport recovered after ${upstreamFailureStreak} failure(s)`);
      }
      resetUpstreamFailureState();
    }
    if (!out.ok && USE_LOCAL_RPC_WHEN_NODE_RUNNING && service.node && walletdRpcTarget !== LOCAL_NODE_RPC) {
      appendLog(win, `[sync] /network failed on ${walletdRpcTarget || RPC_UPSTREAM}; retrying on local RPC ${LOCAL_NODE_RPC}`);
      stopSvc('walletd');
      const restarted = startWalletdOnRpc(win, LOCAL_NODE_RPC);
      if (restarted.ok) {
        await waitMs(900);
        out = await walletdCall('/network', null, { timeoutMs: WALLETD_NETWORK_TIMEOUT_MS });
        if (!out.ok) {
          appendLog(win, `[network] walletd /network retry failed: ${out.error || 'unknown'}`);
        }
      }
    }
    if (out.ok && out.result) {
      // Merge live chain data with local runtime stats (miner count, streak).
      const snap = runtimeNetworkSnapshot();
      let realTip = Number(out.result.tip_height ?? 0);
      if (!Number.isFinite(realTip) || realTip < 0) realTip = 0;
      const tipRegressed =
        realTip > 0
        && lastUpstreamTipSeen > 0
        && realTip + UPSTREAM_TIP_REGRESSION_TOLERANCE < lastUpstreamTipSeen;
      if (tipRegressed) {
        const now = Date.now();
        if (now - lastTipRegressionLogMs > 15000) {
          appendLog(
            win,
            `[network] ignoring regressed telemetry tip=${realTip}; keeping last_seen=${lastUpstreamTipSeen}`
          );
          lastTipRegressionLogMs = now;
        }
        const base = networkTelemetryBaseSnapshot();
        const merged = {
          ...base,
          tip_height: Math.max(lastUpstreamTipSeen, Number(base.tip_height || 0)),
          total_hardening: computeChainHardening(Math.max(lastUpstreamTipSeen, Number(base.tip_height || 0))),
          source: 'cached-telemetry-fallback'
        };
        lastGoodNetworkTelemetry = { ...merged };
        return { ...out, result: merged };
      }
      if (realTip > 0) {
        lastUpstreamTipSeen = Math.max(lastUpstreamTipSeen, realTip);
      }
      const merged = {
        ...out,
        result: {
          ...out.result,
          software_version: DESKTOP_APP_VERSION,
          latest_installer_version: MIN_SUPPORTED_INSTALLER_VERSION,
          min_supported_version: MIN_SUPPORTED_INSTALLER_VERSION,
          min_supported_protocol_version: MIN_SUPPORTED_P2P_PROTOCOL_VERSION,
          total_hardening: computeChainHardening(realTip),
          active_miners_recent: Math.max(Number(out.result.active_miners_recent ?? 0), snap.active_miners_recent),
          tip_proposer_streak: snap.tip_proposer_streak || out.result.tip_proposer_streak || 0,
          recent_blocks: snap.recent_blocks && snap.recent_blocks.length > 0
            ? snap.recent_blocks
            : (out.result.recent_blocks || []),
        }
      };
      lastGoodNetworkTelemetry = { ...merged.result };
      return merged;
    }
    // In explicit local-RPC mode, fall back to log-parsed snapshot if walletd is unreachable.
    if (USE_LOCAL_RPC_WHEN_NODE_RUNNING && service.node) {
      return { ok: true, result: runtimeNetworkSnapshot() };
    }
    // /network can be heavier than /upstream-tip on stressed nodes; keep UI online if tip probe succeeds.
    const tipProbe = await walletdCall('/upstream-tip', null, {
      timeoutMs: Math.min(15000, WALLETD_NETWORK_TIMEOUT_MS)
    });
    if (tipProbe.ok && tipProbe.result) {
      const tipHeight = Number(tipProbe.result.tip_height ?? 0);
      const snap = networkTelemetryBaseSnapshot();
      const mergedTip = Number.isFinite(tipHeight) ? Math.max(tipHeight, Number(snap.tip_height || 0)) : Number(snap.tip_height || 0);
      if (Number.isFinite(mergedTip)) {
        lastUpstreamTipSeen = Math.max(lastUpstreamTipSeen, mergedTip);
      }
      appendLog(win, `[network] using upstream-tip fallback (tip=${mergedTip}) while telemetry is timing out`);
      return {
        ok: true,
        result: {
          ...snap,
          tip_height: mergedTip,
          software_version: DESKTOP_APP_VERSION,
          latest_installer_version: MIN_SUPPORTED_INSTALLER_VERSION,
          min_supported_version: MIN_SUPPORTED_INSTALLER_VERSION,
          min_supported_protocol_version: MIN_SUPPORTED_P2P_PROTOCOL_VERSION,
          total_hardening: computeChainHardening(mergedTip),
          source: 'upstream-tip-fallback'
        }
      };
    }
    return out;
  });
  bindIpc('walletd-fib-wall', 'walletd-fib-wall', (_e, limit = 64) => walletdCall(`/fib-wall?limit=${Number(limit) || 64}`));

  bindIpc('tls-generate', 'tls-generate', () => ensureTls());
  bindIpc('launch-installer', 'launch-installer', () => launchInstallerFromApp(win));
  bindIpc('mining-backends', 'mining-backends', () => ({ ok: true, result: detectMiningBackends() }));
  bindIpc('mining-runtime', 'mining-runtime', () => ({
    ok: true,
    result: {
      mode: runtimeStats.node.miningMode,
      configuredBackend: runtimeStats.node.configuredBackend,
      activeBackend: runtimeStats.node.activeBackend,
      availableBackends: runtimeStats.node.availableBackends,
      activeDevice: runtimeStats.node.activeDevice,
      fallbackActive: runtimeStats.node.fallbackActive,
      lastBackendError: runtimeStats.node.lastBackendError
    }
  }));
  bindIpc('mining-config-get', 'mining-config-get', () => ({ ok: true, result: loadMiningConfig() }));
  bindIpc('mining-config-set', 'mining-config-set', (_e, cfg) => ({ ok: true, result: saveMiningConfig(cfg) }));
  bindIpc('mining-apply-live', 'mining-apply-live', async (_e, profile = null) => {
    const effectiveProfile = profile || miningProfileState || loadMiningConfig().profile;
    miningProfileState = effectiveProfile;
    if (!service.node) return { ok: true, result: 'saved (node not running)' };
    // Detect whether the running node was using a GPU backend before stopping it.
    // CUDA/OpenCL drivers on Windows need extra time to release the GPU context
    // after a forced kill; 300ms is not sufficient for high-end GPUs (e.g. RTX 4090).
    const wasGpu = ['cuda', 'opencl'].includes(
      String(runtimeStats.node.activeBackend || runtimeStats.node.configuredBackend || '').toLowerCase()
    );
    stopSvc('node');
    await waitMs(wasGpu ? 2000 : 400);
    const validatorsPath = ensureValidatorsFile(win);
    const nodeBin = resolveBin('knox-node.exe');
    const minerAddress = await resolveMinerAddress({ requireWalletAddress: !!nodeMineEnabled });
    if (!minerAddress.ok) return minerAddress;
    primeRuntimeNodeForStart(effectiveProfile);
    const restarted = spawnSvc(
      win,
      'node',
      nodeBin,
      nodeArgs(validatorsPath, minerAddress.result),
      nodeDesktopEnv(nodeMineEnabled, effectiveProfile, lastUpstreamTipSeen, minerAddress.result)
    );
    if (!restarted.ok) return restarted;
    appendLog(
      win,
      `[config] live apply mining profile mode=${effectiveProfile.mode || 'hybrid'} backend=${effectiveProfile.backend || 'auto'} diff=${effectiveProfile.difficultyBits} seq=${effectiveProfile.seqSteps} mem=${effectiveProfile.memoryBytes} cpu_util=${effectiveProfile.cpuUtil ?? 'auto'} gpu_util=${effectiveProfile.gpuUtil ?? 'auto'}`
    );
    return { ok: true, result: 'applied live' };
  });
}

app.whenReady().then(async () => {
  ensureDirs();
  purgeLedgerOnVersionChange(mainWindow);
  ensureTls();
  await ensureWalletExists();
  const loaded = loadMiningConfig();
  miningProfileState = loaded.profile;
  desktopMinerAddress = String(loaded.minerAddress || '').trim();
  runtimeStats.node.miningMode = String(loaded.profile?.mode || 'hybrid');
  runtimeStats.node.configuredBackend = String(loaded.profile?.backend || 'auto');
  runtimeStats.node.availableBackends = detectMiningBackends().availableBackends;
  appendLog(mainWindow, '[app] main process ready');
  appendLog(mainWindow, `[startup] rpc_upstream=${RPC_UPSTREAM}`);
  appendLog(mainWindow, `[startup] rpc_candidates=${rpcCandidateList().join(',')}`);
  createWindow();
  if (AUTOSTART_ON_OPEN) {
    setTimeout(async () => {
      const started = await quickStart(mainWindow, miningProfileState || loadMiningConfig().profile);
      if (started.ok) {
        appendLog(mainWindow, '[startup] auto quick start complete');
      } else {
        appendLog(mainWindow, `[startup] auto quick start failed: ${started.error || 'unknown error'}`);
      }
    }, 250);
  } else {
    appendLog(mainWindow, '[startup] auto quick start disabled by KNOX_DESKTOP_AUTOSTART=0');
  }
  app.on('second-instance', () => {
    if (!mainWindow) return;
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
  });
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  shutdownLocalServices();
  if (process.platform !== 'darwin') {
    app.quit();
    setTimeout(() => {
      try { app.exit(0); } catch { }
    }, 800);
  }
});

app.on('before-quit', () => {
  shutdownLocalServices();
});

app.on('will-quit', () => {
  shutdownLocalServices();
});

process.on('exit', () => {
  shutdownLocalServices();
});

process.on('uncaughtException', (err) => {
  appendLog(mainWindow, `[fatal] uncaughtException: ${String(err?.stack || err)}`);
});

process.on('unhandledRejection', (err) => {
  appendLog(mainWindow, `[fatal] unhandledRejection: ${String(err?.stack || err)}`);
});
