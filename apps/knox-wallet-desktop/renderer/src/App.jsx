import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { ErrorBoundary } from './ErrorBoundary';
import * as Tabs from '@radix-ui/react-tabs';
import * as Slider from '@radix-ui/react-slider';
import { motion } from 'framer-motion';
import { create } from 'zustand';
import knocImage from '../../assets/knoc.png';

const useUiStore = create((set) => ({
  view: 'dashboard',
  miningMode: 'hybrid',
  glow: 70,
  setView: (view) => set({ view }),
  setMiningMode: (miningMode) => set({ miningMode }),
  setGlow: (glow) => set({ glow })
}));

const views = ['dashboard', 'mining', 'send', 'logs', 'settings'];

function safeShortAddress(addr) {
  const s = String(addr || '');
  if (s.length < 40) return s || 'N/A';
  return `${s.slice(0, 14)}...${s.slice(-14)}`;
}

function fmtAtoms(v) {
  const n = Number(v || 0);
  if (!Number.isFinite(n)) return '0.00000000';
  return (n / 1e8).toFixed(8);
}

function withTimeout(promise, ms = 1800) {
  let t;
  return Promise.race([
    promise.finally(() => clearTimeout(t)),
    new Promise((resolve) => {
      t = setTimeout(() => resolve({ ok: false, error: 'timeout' }), ms);
    })
  ]);
}

function parseNumericField(raw, label, { integer = false, min = 0, minInclusive = true } = {}) {
  const text = String(raw ?? '').trim();
  if (!text) return { ok: false, error: `${label} is required` };
  if (!/^\d+(\.\d+)?$/.test(text)) return { ok: false, error: `${label} must be numeric` };
  const value = Number(text);
  if (!Number.isFinite(value)) return { ok: false, error: `${label} is invalid` };
  if (integer && !Number.isInteger(value)) return { ok: false, error: `${label} must be an integer` };
  if (minInclusive ? value < min : value <= min) {
    return { ok: false, error: `${label} must be ${minInclusive ? '>=' : '>'} ${min}` };
  }
  return { ok: true, value };
}

function parseIndexedAddressText(raw) {
  const out = [];
  const lines = String(raw || '').split(/\r?\n/);
  for (const line of lines) {
    const indexed = line.match(/#(\d+):\s*(knox1[a-f0-9]{32,})/i);
    if (indexed) {
      out.push({ index: Number(indexed[1]), address: indexed[2] });
      continue;
    }
    const plain = line.match(/knox1[a-f0-9]{32,}/i);
    if (plain) out.push({ index: out.length, address: plain[0] });
  }
  return out;
}

function extractKnoxAddress(raw) {
  const m = String(raw || '').match(/knox1[a-f0-9]{32,}/i);
  return m ? m[0] : '';
}

function runtimeMinerCount(node) {
  const running = Boolean(node?.running);
  if (!running) return 0;
  const mode = String(node?.miningMode || 'hybrid').toLowerCase();
  const backend = String(node?.activeBackend || 'cpu').toLowerCase();
  if (mode === 'hybrid' && backend !== 'cpu') return 2;
  return 1;
}

function formatValue(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return '0';
  if (n >= 1e9) return (n / 1e9).toFixed(2) + 'G';
  if (n >= 1e6) return (n / 1e6).toFixed(2) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  if (n < 0.0001 && n > 0) return n.toExponential(2);
  if (n > 0 && n < 1) return n.toFixed(4);
  return Math.round(n * 100) / 100;
}

function Chart({ title, subtitle, data, lines, empty }) {
  const ref = useRef(null);
  const latestValue = useMemo(() => {
    if (!data.length || !lines.length) return null;
    const last = data[data.length - 1];
    return formatValue(last[lines[0].key]);
  }, [data, lines]);

  useEffect(() => {
    const c = ref.current;
    if (!c) return;
    const ctx = c.getContext('2d');
    if (!ctx) return;

    const dpr = window.devicePixelRatio || 1;
    const w = c.clientWidth || 560;
    const h = c.clientHeight || 220;
    c.width = Math.floor(w * dpr);
    c.height = Math.floor(h * dpr);

    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, c.width, c.height);
    ctx.scale(dpr, dpr);

    const pad = { l: 45, r: 15, t: 15, b: 25 };
    const iw = w - pad.l - pad.r;
    const ih = h - pad.t - pad.b;

    // Grid lines
    ctx.strokeStyle = 'rgba(41,95,129,0.2)';
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i += 1) {
      const y = pad.t + (ih * i) / 4;
      ctx.beginPath();
      ctx.moveTo(pad.l, y);
      ctx.lineTo(w - pad.r, y);
      ctx.stroke();
    }

    const flat = lines.flatMap((line) => data.map((d) => Number(d?.[line.key]))).filter((x) => Number.isFinite(x));
    if (!flat.length) {
      ctx.fillStyle = '#8ea8bf';
      ctx.font = '12px "Space Mono", monospace';
      ctx.fillText(empty, pad.l + 10, h / 2);
      return;
    }

    const min = Math.min(...flat);
    const maxRaw = Math.max(...flat);
    const max = maxRaw === min ? min + 1 : maxRaw;

    // Y-Axis Labels
    ctx.fillStyle = '#8ea8bf';
    ctx.font = '10px "Space Mono", monospace';
    ctx.textAlign = 'right';
    ctx.fillText(formatValue(max), pad.l - 6, pad.t + 4);
    ctx.fillText(formatValue(min + (max - min) / 2), pad.l - 6, pad.t + ih / 2 + 4);
    ctx.fillText(formatValue(min), pad.l - 6, pad.t + ih + 4);

    // X-Axis Labels (start/end)
    ctx.textAlign = 'left';
    ctx.fillText('Past', pad.l, h - 8);
    ctx.textAlign = 'right';
    ctx.fillText('Now', w - pad.r, h - 8);

    // Draw Lines
    for (const line of lines) {
      const vals = data.map((d) => Number(d?.[line.key]));
      ctx.beginPath();
      vals.forEach((v, i) => {
        if (!Number.isFinite(v)) return;
        const x = pad.l + (iw * i) / Math.max(1, vals.length - 1);
        const y = pad.t + (1 - (v - min) / (max - min)) * ih;
        if (i === 0) ctx.moveTo(x, y);
        else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = line.color;
      ctx.lineWidth = 2.5;
      ctx.lineJoin = 'round';
      ctx.stroke();

      // Subtle glow
      ctx.lineWidth = 4;
      ctx.strokeStyle = line.color + '22';
      ctx.stroke();
    }
  }, [data, lines, empty]);

  return (
    <motion.article className="panel" initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.2 }}>
      <header className="panel-head">
        <div>
          <h3>{title}</h3>
          <small>{subtitle}</small>
        </div>
        {latestValue !== null && <div className="panel-value">{latestValue}</div>}
      </header>
      <canvas className="chart" ref={ref} />
    </motion.article>
  );
}

export default function App() {
  const { view, setView, miningMode, setMiningMode, glow, setGlow } = useUiStore();
  const hostCores = Math.max(2, Number((globalThis?.navigator?.hardwareConcurrency) || 24));
  const [logLines, setLogLines] = useState([]);
  const [actionStatus, setActionStatus] = useState('Ready.');
  const [busyAction, setBusyAction] = useState('');
  const [miningPreset, setMiningPreset] = useState('balanced');
  const [miningBackend, setMiningBackend] = useState('auto');
  const logoCandidates = [knocImage];
  const [logoIdx] = useState(0);
  const [sendForm, setSendForm] = useState({ to: '', amount: '0', fee: '1', ring: '31' });
  const [sliders, setSliders] = useState({ cpuCores: 12, cpuUtil: 70, gpuUtil: 70, vram: 60 });
  const [gpuDeviceId, setGpuDeviceId] = useState(0);
  const [cudaDeviceOrdinal, setCudaDeviceOrdinal] = useState(0);
  const [advanced, setAdvanced] = useState({
    scheduleEnabled: false,
    surgeAutoMax: true,
    tempThrottle: true,
    powerCostPerKwh: 0.12
  });
  const [configReady, setConfigReady] = useState(false);
  const [samples, setSamples] = useState([]);
  const [blocks, setBlocks] = useState([]);
  const [selectedMinerAddressLive, setSelectedMinerAddressLive] = useState('');
  const [showDebugWalletTools, setShowDebugWalletTools] = useState(false);
  const [importNodeKeyPath, setImportNodeKeyPath] = useState('');
  const [addressOverride, setAddressOverride] = useState('');
  const [scanQrOpen, setScanQrOpen] = useState(false);
  const [scanQrError, setScanQrError] = useState('');
  const scanVideoRef = useRef(null);
  const scanStreamRef = useRef(null);
  const scanFrameRef = useRef(0);
  const lastRuntimeHeightRef = useRef(null);
  const logoSrc = logoCandidates[Math.min(logoIdx, logoCandidates.length - 1)];
  const heroSrc = knocImage;

  useEffect(() => {
    if (!window.knox?.onLog) return;
    const off = window.knox.onLog((line) => {
      setLogLines((prev) => [...prev.slice(-400), `[${new Date().toLocaleTimeString()}] ${line}`]);
    });
    return () => {
      if (typeof off === 'function') off();
    };
  }, []);

  useEffect(() => {
    document.documentElement.style.setProperty('--glow-intensity', `${glow / 100}`);
  }, [glow]);

  function stopQrScanner() {
    if (scanFrameRef.current) {
      cancelAnimationFrame(scanFrameRef.current);
      scanFrameRef.current = 0;
    }
    if (scanStreamRef.current) {
      for (const track of scanStreamRef.current.getTracks()) {
        track.stop();
      }
      scanStreamRef.current = null;
    }
    if (scanVideoRef.current) {
      scanVideoRef.current.srcObject = null;
    }
  }

  async function startQrScanner() {
    setScanQrError('');
    if (!navigator?.mediaDevices?.getUserMedia) {
      setScanQrError('Camera access is not available on this system.');
      return;
    }
    const Detector = globalThis.BarcodeDetector;
    if (!Detector) {
      setScanQrError('QR scanning is not supported by this runtime build.');
      return;
    }

    try {
      const detector = new Detector({ formats: ['qr_code'] });
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: { ideal: 'environment' } },
        audio: false
      });
      scanStreamRef.current = stream;
      const video = scanVideoRef.current;
      if (!video) {
        stopQrScanner();
        setScanQrError('Scanner video surface failed to initialize.');
        return;
      }
      video.srcObject = stream;
      await video.play();

      const tick = async () => {
        try {
          const codes = await detector.detect(video);
          if (Array.isArray(codes) && codes.length) {
            const raw = String(codes[0].rawValue || '').trim();
            const parsed = extractKnoxAddress(raw) || raw;
            if (parsed) {
              setSendForm((prev) => ({ ...prev, to: parsed }));
              setActionStatus(`Success: QR Scan - ${safeShortAddress(parsed)}`);
              setScanQrOpen(false);
              stopQrScanner();
              return;
            }
          }
        } catch (err) {
          setScanQrError(String(err?.message || err));
          setScanQrOpen(false);
          stopQrScanner();
          return;
        }
        scanFrameRef.current = requestAnimationFrame(tick);
      };
      scanFrameRef.current = requestAnimationFrame(tick);
    } catch (err) {
      stopQrScanner();
      setScanQrError(String(err?.message || err));
    }
  }

  useEffect(() => {
    let dead = false;
    (async () => {
      const res = await window.knox.miningConfigGet();
      if (!res?.ok || dead) {
        if (!dead) setConfigReady(true);
        return;
      }
      const cfg = res.result || {};
      if (cfg.mode) setMiningMode(String(cfg.mode).toLowerCase());
      if (cfg.backend) setMiningBackend(String(cfg.backend).toLowerCase());
      if (cfg.preset) setMiningPreset(String(cfg.preset).toLowerCase());
      setSliders((prev) => ({
        ...prev,
        cpuCores: Number.isFinite(Number(cfg.cpuCores)) ? Number(cfg.cpuCores) : prev.cpuCores,
        cpuUtil: Number.isFinite(Number(cfg.cpuUtil)) ? Number(cfg.cpuUtil) : prev.cpuUtil,
        gpuUtil: Number.isFinite(Number(cfg.gpuUtil)) ? Number(cfg.gpuUtil) : prev.gpuUtil,
        vram: Number.isFinite(Number(cfg.vram)) ? Number(cfg.vram) : prev.vram,
      }));
      setGpuDeviceId(Number.isFinite(Number(cfg.gpuDeviceId)) ? Number(cfg.gpuDeviceId) : 0);
      setCudaDeviceOrdinal(Number.isFinite(Number(cfg.cudaDeviceOrdinal)) ? Number(cfg.cudaDeviceOrdinal) : 0);
      setAdvanced({
        scheduleEnabled: Boolean(cfg.scheduleEnabled),
        surgeAutoMax: cfg.surgeAutoMax !== false,
        tempThrottle: cfg.tempThrottle !== false,
        powerCostPerKwh: Number.isFinite(Number(cfg.powerCostPerKwh)) ? Number(cfg.powerCostPerKwh) : 0.12
      });
      setConfigReady(true);
    })();
    return () => { dead = true; };
  }, [setMiningMode]);

  useEffect(() => {
    let dead = false;
    (async () => {
      const out = await window.knox.minerAddressGet();
      if (dead || !out?.ok) return;
      setSelectedMinerAddressLive(String(out.result || ''));
    })();
    return () => { dead = true; };
  }, []);

  useEffect(() => {
    if (!scanQrOpen) {
      stopQrScanner();
      return;
    }
    void startQrScanner();
    return () => stopQrScanner();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scanQrOpen]);

  const serviceQ = useQuery({
    queryKey: ['service'],
    queryFn: () => window.knox.serviceState(),
    refetchInterval: 10000
  });

  const onboardQ = useQuery({
    queryKey: ['onboard'],
    queryFn: () => window.knox.onboardingState(),
    refetchInterval: false
  });

  const runtimeQ = useQuery({
    queryKey: ['runtime'],
    queryFn: () => window.knox.nodeRuntimeStats(),
    refetchInterval: 3000
  });

  const backendQ = useQuery({
    queryKey: ['miningBackends'],
    queryFn: () => window.knox.miningBackends(),
    refetchInterval: 15000
  });

  const walletInfoQ = useQuery({
    queryKey: ['walletInfo'],
    queryFn: () => window.knox.walletdInfo(),
    enabled: true,
    refetchInterval: 10000
  });

  const netQ = useQuery({
    queryKey: ['network'],
    queryFn: () => window.knox.walletdNetwork(),
    enabled: true,
    refetchInterval: 10000
  });

  const fibQ = useQuery({
    queryKey: ['fib'],
    queryFn: () => window.knox.walletdFibWall(64),
    enabled: true,
    refetchInterval: 20000
  });

  const walletHealthQ = useQuery({
    queryKey: ['walletHealth'],
    queryFn: () => window.knox.walletdHealth(),
    enabled: true,
    refetchInterval: 15000
  });

  const walletAddrIndexedQ = useQuery({
    queryKey: ['walletAddressesIndexed'],
    queryFn: () => window.knox.walletdAddresses(),
    enabled: true,
    refetchInterval: 20000
  });

  const walletAddressesTextQ = useQuery({
    queryKey: ['walletAddressesText'],
    queryFn: () => window.knox.walletAddresses(),
    enabled: true,
    refetchInterval: 25000
  });

  const walletAddressQ = useQuery({
    queryKey: ['walletAddress'],
    queryFn: () => window.knox.walletAddress(),
    enabled: true,
    refetchInterval: 20000
  });

  useEffect(() => {
    const net = netQ.data;
    if (!net?.ok || !net.result) return;
    const n = net.result;
    const tipHeight = Number(n.tip_height ?? n.height ?? n.last_height ?? 0);
    const miners = Number(n.active_miners_recent ?? n.active_miners ?? n.miners ?? 0);
    const difficulty = Number(n.current_difficulty_bits ?? n.difficulty_bits ?? n.difficulty ?? 0);
    const streak = Number(n.tip_proposer_streak ?? n.current_streak ?? n.streak ?? 0);
    const nextStreak = Number(n.next_streak_if_same_proposer ?? 0);
    const bonus = Number(n.streak_bonus_ppm ?? n.bonus ?? 0);
    const hardening = Number(n.total_hardening ?? n.hardening ?? 0);
    const surgePhase = String(n.surge_phase ?? '').toLowerCase();
    const surgeActive = Boolean(
      n.surge_active ??
      n.surge ??
      (surgePhase && surgePhase !== 'none' && surgePhase !== 'idle' && surgePhase !== 'off')
    );
    const attempts = Number(
      n.attempts_per_sec ??
      n.hashrate ??
      (miners > 0 && difficulty > 0 ? miners * Math.max(1, Math.floor(difficulty / 2)) : 0)
    );

    const sample = {
      at: Date.now(),
      height: tipHeight,
      attempts,
      difficulty,
      hardening,
      reward: Number(n.reward_now ?? n.reward ?? nextStreak ?? 0),
      streak,
      bonus,
      miners,
      surge: surgeActive,
      source: 'network'
    };
    setSamples((prev) => [...prev.slice(-140), sample]);

    if (Array.isArray(n.recent_blocks) && n.recent_blocks.length) {
      setBlocks(
        n.recent_blocks.slice(0, 20).map((b) => ({
          ...b,
          time: Number.isFinite(Number(b.time))
            ? new Date(Number(b.time)).toLocaleTimeString()
            : (b.time || '--:--:--')
        }))
      );
    }
  }, [netQ.data]);

  useEffect(() => {
    const runtimeNode = runtimeQ.data?.result?.node;
    if (!runtimeNode) return;
    const estAttempts = Math.round(
      sliders.cpuCores * (16 + sliders.cpuUtil * 1.6) +
      sliders.gpuUtil * 22 +
      sliders.vram * 9
    );
    const sealedHeight = Number(runtimeNode.lastSealedHeight);
    if (!Number.isFinite(sealedHeight)) return;
    if (lastRuntimeHeightRef.current === sealedHeight) return;
    lastRuntimeHeightRef.current = sealedHeight;

    const sample = {
      at: Date.now(),
      height: sealedHeight,
      attempts: Number(runtimeNode.running ? estAttempts : 0),
      difficulty: Number(runtimeNode.currentDifficultyBits || 0),
      hardening: Number(runtimeNode.totalHardeningEstimate || 0),
      reward: 0,
      streak: Number(runtimeNode.currentStreak || 0),
      bonus: 0,
      miners: Number(runtimeMinerCount(runtimeNode)),
      surge: false,
      source: 'runtime'
    };
    setSamples((prev) => [...prev.slice(-140), sample]);

    if (Array.isArray(runtimeNode.recentBlocks) && runtimeNode.recentBlocks.length) {
      setBlocks(
        runtimeNode.recentBlocks.slice(0, 20).map((b) => ({
          ...b,
          height: Number(b.height || 0),
          status: b.status || 'SEALED',
          meta: b.meta || `${Number(b.txs || 0)} tx`,
          time: b.time || '--:--:--'
        }))
      );
    }
  }, [runtimeQ.data, sliders.cpuCores, sliders.cpuUtil, sliders.gpuUtil, sliders.vram]);

  const status = serviceQ.data?.result || {};
  const runtime = runtimeQ.data?.result || status.runtime || {};
  const runtimeNode = runtime.node || {};
  const runtimeWalletd = runtime.walletd || {};
  const backendInfo = backendQ.data?.result || { availableBackends: ['cpu'], preferredBackend: 'cpu', devices: [] };
  const availableBackends = ['auto', ...Array.from(new Set((backendInfo.availableBackends || ['cpu']).map((v) => String(v).toLowerCase())))];
  const activeBackendLabel = String(runtimeNode.activeBackend || 'cpu').toUpperCase();
  const configuredBackendLabel = String(runtimeNode.configuredBackend || miningBackend || 'auto').toUpperCase();
  const runtimeFallback = Boolean(runtimeNode.fallbackActive);
  const runtimeBackendError = String(runtimeNode.lastBackendError || '');
  const selectedMinerAddress = String(selectedMinerAddressLive || status.selectedMinerAddress || '');
  const onboarding = onboardQ.data?.result || {};
  const info = walletInfoQ.data?.result || {};
  const infoOk = walletInfoQ.data?.ok;
  const walletHealth = walletHealthQ.data?.result || {};
  const infoAddresses = useMemo(() => {
    if (Array.isArray(info.addresses) && info.addresses.length) {
      return info.addresses.map((a) => String(a || '').trim()).filter(Boolean);
    }
    if (info.address) return [String(info.address)];
    return [];
  }, [info]);

  const indexedAddresses = useMemo(() => {
    const merged = new Map();
    const push = (index, address) => {
      const addr = String(address || '').trim();
      if (!addr) return;
      if (!merged.has(addr)) {
        merged.set(addr, {
          index: Number.isFinite(Number(index)) ? Number(index) : merged.size,
          address: addr
        });
      }
    };

    const rpcResult = walletAddrIndexedQ.data?.result;
    if (Array.isArray(rpcResult)) {
      rpcResult.forEach((entry, i) => push(entry?.index ?? i, entry?.address));
    }

    const textParsed = parseIndexedAddressText(walletAddressesTextQ.data?.result);
    textParsed.forEach((entry, i) => push(entry.index ?? i, entry.address));

    infoAddresses.forEach((address, i) => push(i, address));
    const direct = extractKnoxAddress(walletAddressQ.data?.result);
    if (direct) push(0, direct);

    return Array.from(merged.values()).sort((a, b) => a.index - b.index);
  }, [walletAddrIndexedQ.data, walletAddressesTextQ.data, walletAddressQ.data, infoAddresses]);

  const addresses = useMemo(
    () => indexedAddresses.map((entry) => entry.address),
    [indexedAddresses]
  );

  const directAddress = useMemo(
    () => extractKnoxAddress(walletAddressQ.data?.result),
    [walletAddressQ.data]
  );

  const primaryAddress = useMemo(
    () => addressOverride || info.address || addresses[0] || directAddress || '',
    [addressOverride, info.address, addresses, directAddress]
  );

  useEffect(() => {
    setSelectedMinerAddressLive(String(status.selectedMinerAddress || ''));
  }, [status.selectedMinerAddress]);

  const telemetry = useMemo(() => {
    const net = netQ.data?.result || {};
    const latest = samples[samples.length - 1] || {};
    const netDifficulty = Number(net.current_difficulty_bits);
    const netHardening = Number(net.total_hardening);
    const netMiners = Number(net.active_miners_recent);
    const netStreak = Number(net.tip_proposer_streak);
    const runtimeHeight = Number(runtimeNode.lastSealedHeight || 0);
    const runtimeDifficulty = Number(runtimeNode.currentDifficultyBits || 0);
    const runtimeHardening = Number(runtimeNode.totalHardeningEstimate || 0);
    const runtimeStreak = Number(runtimeNode.currentStreak || 0);
    const runtimeMiners = runtimeMinerCount(runtimeNode);
    const fallbackHeight = Number.isFinite(runtimeHeight) ? runtimeHeight : 0;
    const latestDifficulty = Number(latest.difficulty);
    const latestHardening = Number(latest.hardening);
    const latestMiners = Number(latest.miners);
    const latestStreak = Number(latest.streak);
    return {
      height: (Number.isFinite(latest.height) && latest.height > 0)
        ? latest.height
        : (runtimeHeight > 0 ? runtimeHeight : Number(net.tip_height ?? info.last_height ?? 0)),
      attempts: Number.isFinite(latest.attempts) ? latest.attempts : Number(net.attempts_per_sec ?? 0),
      difficulty: Number.isFinite(netDifficulty) && netDifficulty > 0
        ? netDifficulty
        : (Number.isFinite(latestDifficulty) && latestDifficulty > 0 ? latestDifficulty : runtimeDifficulty),
      hardening: Number.isFinite(netHardening) && netHardening > 0
        ? netHardening
        : (Number.isFinite(latestHardening) && latestHardening > 0 ? latestHardening : runtimeHardening),
      reward: Number.isFinite(latest.reward) ? latest.reward : Number(net.reward_now ?? 0),
      streak: !runtimeNode.running ? 0 : runtimeStreak,
      bonus: Number.isFinite(latest.bonus) ? latest.bonus : Number(net.streak_bonus_ppm ?? 0),
      miners: Number.isFinite(netMiners) && netMiners > 0
        ? netMiners
        : (Number.isFinite(latestMiners) && latestMiners > 0 ? latestMiners : runtimeMiners),
      surge: latest.surge ? 'Active' : 'Idle'
    };
  }, [
    samples,
    info,
    netQ.data,
    runtimeNode.lastSealedHeight,
    runtimeNode.currentDifficultyBits,
    runtimeNode.totalHardeningEstimate,
    runtimeNode.currentStreak,
    runtimeNode.running
  ]);

  useEffect(() => {
    if (availableBackends.includes(miningBackend)) return;
    setMiningBackend('auto');
  }, [availableBackends, miningBackend]);

  function numOrNa(value) {
    return Number.isFinite(Number(value)) ? Number(value) : 'N/A';
  }

  const performance = useMemo(() => {
    const hashRate = Math.round(
      sliders.cpuCores * (16 + sliders.cpuUtil * 1.6) +
      sliders.gpuUtil * 22 +
      sliders.vram * 9
    );
    const power = Math.round(
      sliders.cpuCores * 9 +
      sliders.cpuUtil * 1.8 +
      sliders.gpuUtil * 3.1 +
      sliders.vram * 1.2
    );
    const costDay = ((power / 1000) * 24 * Number(advanced.powerCostPerKwh || 0.12));
    const knoxDay = (hashRate / 260).toFixed(2);
    return { hashRate, power, costDay, knoxDay };
  }, [sliders, advanced.powerCostPerKwh]);

  const metricPills = [
    { label: 'Height', value: (telemetry.height || 0).toLocaleString(), tone: 'cyan' },
    { label: 'Balance', value: `${fmtAtoms(info.balance || 0)} KNOX`, tone: 'cyan' },
    { label: 'Miners', value: numOrNa(telemetry.miners), tone: 'green' },
    { label: 'Difficulty', value: telemetry.difficulty ? telemetry.difficulty.toFixed(6) : 'N/A', tone: 'cyan' },
    { label: 'Streak', value: numOrNa(telemetry.streak), tone: 'pink' },
    { label: 'Hardening', value: numOrNa(telemetry.hardening), tone: 'amber' },
    { label: 'Bonus', value: numOrNa(telemetry.bonus), tone: 'amber' },
    { label: 'Surge', value: telemetry.surge, tone: telemetry.surge === 'Active' ? 'pink' : 'cyan' },
    { label: 'Source', value: netQ.data?.ok ? 'Network' : (runtimeNode.running || Number.isFinite(Number(runtimeNode.lastSealedHeight)) ? 'Local Node' : 'N/A'), tone: netQ.data?.ok ? 'green' : 'amber' },
    { label: 'RPC', value: status.walletdRunning ? 'Online' : 'Offline', tone: status.walletdRunning ? 'green' : 'pink' },
  ];

  function miningProfileFromUi() {
    const util = Math.max(1, Math.round((sliders.cpuUtil + sliders.gpuUtil) / 2));
    // Higher utilization should increase work depth, not lower it.
    const difficultyBits = Math.max(6, Math.min(20, Math.round(6 + util / 10)));
    const seqSteps = Math.max(16, Math.min(4096, sliders.cpuCores * 32));
    const memoryBytes = Math.max(
      4 * 1024 * 1024,
      Math.min(256 * 1024 * 1024, (8 + Math.round(sliders.vram * 0.56)) * 1024 * 1024)
    );
    return {
      difficultyBits,
      seqSteps,
      memoryBytes,
      mode: miningMode,
      backend: miningBackend,
      cpuUtil: sliders.cpuUtil,
      gpuUtil: sliders.gpuUtil,
      gpuDeviceId,
      cudaDeviceOrdinal
    };
  }

  async function saveMiningConfig() {
    const payload = {
      mode: miningMode,
      backend: miningBackend,
      preset: miningPreset,
      cpuCores: sliders.cpuCores,
      cpuUtil: sliders.cpuUtil,
      gpuUtil: sliders.gpuUtil,
      vram: sliders.vram,
      gpuDeviceId,
      cudaDeviceOrdinal,
      scheduleEnabled: advanced.scheduleEnabled,
      surgeAutoMax: advanced.surgeAutoMax,
      tempThrottle: advanced.tempThrottle,
      powerCostPerKwh: advanced.powerCostPerKwh,
      profile: miningProfileFromUi(),
    };
    return window.knox.miningConfigSet(payload);
  }

  useEffect(() => {
    if (!configReady) return;
    const id = setTimeout(() => {
      saveMiningConfig();
    }, 500);
    return () => clearTimeout(id);
  }, [
    configReady,
    miningMode,
    miningBackend,
    miningPreset,
    sliders.cpuCores,
    sliders.cpuUtil,
    sliders.gpuUtil,
    sliders.vram,
    gpuDeviceId,
    cudaDeviceOrdinal,
    advanced.scheduleEnabled,
    advanced.surgeAutoMax,
    advanced.tempThrottle,
    advanced.powerCostPerKwh
  ]);

  async function act(label, fn) {
    if (busyAction) return;
    setBusyAction(label);
    setActionStatus(`Running: ${label}...`);
    try {
      const res = await fn();
      if (res?.ok) {
        const successText = typeof res.result === 'string' && res.result.trim()
          ? `Success: ${label} - ${res.result}`
          : `Success: ${label}`;
        setActionStatus(successText);
        setLogLines((prev) => [
          ...prev.slice(-400),
          `[${new Date().toLocaleTimeString()}] [ui] ${label}: ${typeof res.result === 'string' ? res.result : 'ok'}`
        ]);
        serviceQ.refetch();
        walletInfoQ.refetch();
        netQ.refetch();
        fibQ.refetch();
        runtimeQ.refetch();
        backendQ.refetch();
        walletHealthQ.refetch();
        walletAddrIndexedQ.refetch();
        walletAddressesTextQ.refetch();
        walletAddressQ.refetch();
        return;
      }
      setActionStatus(`Error: ${label} - ${res?.error || 'unknown error'}`);
      setLogLines((prev) => [
        ...prev.slice(-400),
        `[${new Date().toLocaleTimeString()}] [ui] ${label}: ${res?.error || 'unknown error'}`
      ]);
    } catch (err) {
      setActionStatus(`Error: ${label} - ${String(err?.message || err)}`);
      setLogLines((prev) => [
        ...prev.slice(-400),
        `[${new Date().toLocaleTimeString()}] [ui] ${label}: ${String(err?.message || err)}`
      ]);
    } finally {
      setBusyAction('');
    }
  }

  function applyPreset(preset) {
    const full = hostCores;
    const half = Math.max(1, Math.floor(full * 0.5));
    const quarter = Math.max(1, Math.floor(full * 0.25));
    const table = {
      maximum: { mode: 'hybrid', backend: 'auto', cpuCores: full, cpuUtil: 100, gpuUtil: 100, vram: 95 },
      balanced: { mode: 'hybrid', backend: 'auto', cpuCores: half, cpuUtil: 50, gpuUtil: 75, vram: 60 },
      eco: { mode: 'cpu', backend: 'cpu', cpuCores: quarter, cpuUtil: 25, gpuUtil: 1, vram: 1 },
      gaming: { mode: 'cpu', backend: 'cpu', cpuCores: half, cpuUtil: 50, gpuUtil: 1, vram: 1 },
      custom: null
    };
    const next = table[preset];
    setMiningPreset(preset);
    if (!next) return;
    setMiningMode(next.mode);
    setMiningBackend(next.backend);
    setSliders({
      cpuCores: next.cpuCores,
      cpuUtil: next.cpuUtil,
      gpuUtil: next.gpuUtil,
      vram: next.vram
    });
    setActionStatus(`Preset applied: ${preset.toUpperCase()}`);
  }

  function setSliderAndMarkCustom(key, value) {
    setSliders((s) => ({ ...s, [key]: value }));
    setMiningPreset('custom');
  }

  async function copyAddressToClipboard(address) {
    const value = String(address || '').trim();
    if (!value) {
      setActionStatus('Error: Copy Address - empty address');
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      setActionStatus(`Success: Copy Address - ${safeShortAddress(value)}`);
    } catch (err) {
      setActionStatus(`Error: Copy Address - ${String(err?.message || err)}`);
    }
  }

  useEffect(() => {
    if (!advanced.surgeAutoMax) return;
    if (String(telemetry.surge || '').toLowerCase() !== 'active') return;
    applyPreset('maximum');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [telemetry.surge, advanced.surgeAutoMax]);

  useEffect(() => {
    if (!advanced.scheduleEnabled) return;
    const tick = async () => {
      const now = new Date();
      const hh = now.getHours();
      let target = 'balanced';
      if (hh >= 23 || hh < 8) target = 'maximum';
      else if (hh >= 18 && hh < 23) target = 'gaming';
      else target = 'eco';
      if (target === miningPreset) return;
      applyPreset(target);
      await saveMiningConfig();
      if (status.nodeRunning) {
        await window.knox.miningApplyLive(miningProfileFromUi());
      }
    };
    tick();
    const id = setInterval(tick, 30000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [advanced.scheduleEnabled, miningPreset, status.nodeRunning]);

  const heroButtons = [
    ['Quick Start', () => window.knox.quickStart(miningProfileFromUi())],
    ['Generate TLS', () => window.knox.tlsGenerate()],
    ['Start Node (Mining On)', () => window.knox.startNode(true, miningProfileFromUi())],
    ['Start Node (Mining Off)', () => window.knox.startNode(false)],
    ['Stop Node', () => window.knox.stopService('node')],
    ['Start Wallet', () => window.knox.startWalletd()],
    ['Stop Wallet', () => window.knox.stopService('walletd')],
    ['Create Wallet', () => window.knox.walletCreate()],
    ['Restore Latest Backup', () => window.knox.walletBackupRestoreLatest()],
    ['Get Wallet Address', async () => {
      // deduplicate/throttle logic for address fetching
      const parseAndReturn = (raw) => {
        if (!raw) return null;
        const addr = extractKnoxAddress(raw);
        if (!addr) return null;
        setAddressOverride(addr);
        return { ok: true, result: addr };
      };

      try {
        // Try direct wallet address first
        const direct = await withTimeout(window.knox.walletAddress(), 4000);
        const directParsed = parseAndReturn(direct?.result);
        if (directParsed) return directParsed;

        // Try wallet daemon addresses list
        const indexed = await withTimeout(window.knox.walletdAddresses(), 4000);
        if (indexed?.ok && Array.isArray(indexed.result) && indexed.result.length) {
          const addr = String(indexed.result[0]?.address || '').trim();
          if (addr) {
            setAddressOverride(addr);
            return { ok: true, result: addr };
          }
        }

        // Try CLI list if all else fails
        const list = await withTimeout(window.knox.walletAddresses(), 6000);
        const listParsed = parseAndReturn(list?.result);
        if (listParsed) return listParsed;

        return {
          ok: false,
          error: direct?.error || indexed?.error || list?.error || 'No addresses found in wallet.'
        };
      } catch (err) {
        return { ok: false, error: String(err?.message || err) };
      }
    }],
    ['New Address', () => window.knox.walletNewAddress()],
    ['List Addresses', () => window.knox.walletAddresses()],
    ['Sync Wallet', () => window.knox.walletSync()],
    ['Rescan Wallet', () => window.knox.walletRescan()],
    ['Get Balance', () => window.knox.walletBalance()],
    ['Wallet Health', () => window.knox.walletdHealth()],
    ['Wallet Addresses', () => window.knox.walletdAddresses()],
    ['Refresh Info', async () => {
      await Promise.allSettled([
        withTimeout(serviceQ.refetch(), 1500),
        withTimeout(onboardQ.refetch(), 1500),
        withTimeout(walletInfoQ.refetch(), 1500),
        withTimeout(netQ.refetch(), 1500),
        withTimeout(fibQ.refetch(), 1500),
        withTimeout(runtimeQ.refetch(), 1500),
        withTimeout(backendQ.refetch(), 1500),
        withTimeout(walletHealthQ.refetch(), 1500),
        withTimeout(walletAddrIndexedQ.refetch(), 1500),
        withTimeout(walletAddressesTextQ.refetch(), 1500),
        withTimeout(walletAddressQ.refetch(), 1500),
      ]);
      return { ok: true, result: 'refreshed' };
    }]
  ];

  return (
    <div className="app">
      <div
        className="nebula"
        style={{
          backgroundImage: `linear-gradient(145deg, rgba(4, 9, 25, 0.58), rgba(10, 18, 42, 0.62) 45%, rgba(8, 18, 40, 0.56)), radial-gradient(1000px 700px at 15% -20%, rgba(255, 53, 210, calc(0.20 * var(--glow-intensity))), transparent 65%), radial-gradient(1200px 900px at 100% 110%, rgba(0, 229, 255, calc(0.24 * var(--glow-intensity))), transparent 65%), url(${heroSrc})`,
          backgroundSize: 'cover, auto, auto, cover',
          backgroundPosition: 'center, center, center, center',
          backgroundRepeat: 'no-repeat, no-repeat, no-repeat, no-repeat',
          backgroundBlendMode: 'normal, screen, screen, normal'
        }}
      />
      <aside className="sidebar">
        <div className="logo-card">
          <img className="logo-img" src={logoSrc} alt="KNOX" />
          <div>
            <div className="logo-title">KNOX</div>
            <div className="logo-sub">WALLET</div>
          </div>
        </div>

        <nav className="sidebar-nav">
          {views.map((v) => (
            <button key={v} className={`side-btn ${view === v ? 'active' : ''}`} onClick={() => setView(v)}>
              {v[0].toUpperCase() + v.slice(1)}
            </button>
          ))}
        </nav>

        <div className="version">Inquiries: KNOXULT7Rock@proton.me<br />KNOX Wallet v1.2.2</div>
      </aside>

      <ErrorBoundary>
        <main className="main">
          <header className="pill-row">
            {metricPills.map((m) => (
              <span key={m.label} className={`pill pill-${m.tone}`}>
                {m.label} <b>{m.value}</b>
              </span>
            ))}
          </header>

          {view === 'dashboard' && (
            <>
              <section className="hero-actions card">
                <div className="action-grid hero-grid">
                  {heroButtons.map(([name, fn]) => {
                    const danger = /^Stop /.test(name);
                    return (
                      <button
                        key={name}
                        className={`action-btn ${danger ? 'action-danger' : ''}`}
                        onClick={() => act(name, fn)}
                        disabled={Boolean(busyAction)}
                      >
                        {busyAction === name ? `${name}...` : name}
                      </button>
                    );
                  })}
                </div>
                <div className="action-status">{actionStatus}</div>
              </section>

              <section className="grid two">
                <Chart title="Chain Height" subtitle="Over Time" data={samples} lines={[{ key: 'height', color: '#04d9ff' }]} empty="Waiting for chain data..." />
                <Chart title="Attempts / Sec" subtitle="Throughput" data={samples} lines={[{ key: 'attempts', color: '#ff3fd7' }]} empty="Waiting for miner data..." />
                <Chart title="Difficulty" subtitle="+ Hardening" data={samples} lines={[{ key: 'difficulty', color: '#04d9ff' }, { key: 'hardening', color: '#ffca5e' }]} empty="Waiting for difficulty data..." />
                <Chart title="Rewards & Streak" subtitle="Timeline" data={samples} lines={[{ key: 'reward', color: '#2ef8a4' }, { key: 'streak', color: '#04d9ff' }]} empty="Waiting for rewards data..." />
              </section>
              {netQ.data && !netQ.data.ok && !(runtimeNode.running || Number.isFinite(Number(runtimeNode.lastSealedHeight))) && (
                <section className="card panel">
                  <h3>Telemetry Error</h3>
                  <pre className="mono-box">{String(netQ.data.error || 'network telemetry unavailable')}</pre>
                </section>
              )}

              <section className="grid two">
                <article className="card panel">
                  <h3>Recent Blocks</h3>
                  <div className="recent-list">
                    {blocks.length === 0 && <div className="recent-row"><span>--</span><span>No data yet</span><span>WAIT</span><span>--</span></div>}
                    {blocks.slice(0, 10).map((b, i) => (
                      <div className="recent-row" key={`${b.height || i}-${i}`}>
                        <span>{b.time || '--:--:--'}</span>
                        <span>#{Number(b.height || 0).toLocaleString()}</span>
                        <span>{b.status || 'SEALED'}</span>
                        <span>{b.meta || `${b.txs || 0} tx`}</span>
                      </div>
                    ))}
                  </div>
                </article>

                <article className="card panel">
                  <h3>System Health</h3>
                  <div className="health-grid">
                    <div><span>Node</span><b className={status.nodeRunning ? 'state-running' : 'state-stopped'}>{status.nodeRunning ? 'Running' : 'Stopped'}</b></div>
                    <div><span>Wallet</span><b className={status.walletdRunning ? 'state-running' : 'state-stopped'}>{status.walletdRunning ? 'Running' : 'Stopped'}</b></div>
                    <div><span>RPC</span><b>{status.rpcAddress || 'N/A'}</b></div>
                    <div><span>Wallet Path</span><b className="small">{status.walletPath || 'N/A'}</b></div>
                    <div><span>Mining</span><b className={status.miningEnabled ? 'state-running' : 'state-stopped'}>{status.miningEnabled ? 'Enabled' : 'Disabled'}</b></div>
                    <div><span>Mining Config</span><b className="small">{status.miningConfigPath || 'N/A'}</b></div>
                    <div><span>Last Sealed</span><b>{Number.isFinite(Number(runtimeNode.lastSealedHeight)) ? `#${Number(runtimeNode.lastSealedHeight).toLocaleString()}` : 'N/A'}</b></div>
                    <div><span>Wallet Listener</span><b className={runtimeWalletd.listening ? 'state-running' : 'state-stopped'}>{runtimeWalletd.listening ? 'Ready' : 'Not Ready'}</b></div>
                    <div><span>Last Propose</span><b>{Number.isFinite(Number(runtimeNode.lastProposeHeight)) ? `h=${runtimeNode.lastProposeHeight} r=${runtimeNode.lastProposeRound ?? 0}` : 'N/A'}</b></div>
                    <div><span>Last Reject</span><b className="small">{runtimeNode.lastReject || runtimeWalletd.lastInfoError || runtimeWalletd.lastSyncError || 'None'}</b></div>
                  </div>
                </article>
              </section>

              <section className="grid two">
                <article className="card panel">
                  <h3>Onboarding</h3>
                  <pre className="mono-box">
                    Node Binary: {onboarding.nodeBinaryReady ? 'Ready' : 'Missing'}
                    Node Path: {onboarding.nodePath || 'N/A'}
                    Wallet Binary: {onboarding.walletBinaryReady ? 'Ready' : 'Missing'}
                    Wallet Path: {onboarding.walletPath || 'N/A'}
                    Wallet CLI Binary: {onboarding.walletCliBinaryReady ? 'Ready' : 'Missing'}
                    Wallet CLI Path: {onboarding.walletCliPath || 'N/A'}
                    Mining Config: {onboarding.miningConfigReady ? 'Ready' : 'Missing'}
                    Mining Config Path: {onboarding.miningConfigPath || 'N/A'}
                    TLS Certificate: {onboarding.tlsCertReady ? 'Ready' : 'Missing'}
                    TLS Key: {onboarding.tlsKeyReady ? 'Ready' : 'Missing'}
                    Wallet File: {onboarding.walletFileReady ? 'Ready' : 'Missing'}
                  </pre>
                </article>

                <article className="card panel">
                  <h3>Wallet Info</h3>
                  <pre className="mono-box">
                    Address: {primaryAddress ? safeShortAddress(primaryAddress) : 'N/A'}
                    Address Count: {addresses.length}
                    Indexed Address Count: {indexedAddresses.length}
                    Balance: {fmtAtoms(info.balance || 0)} KNOX
                    Last Height: {Number(info.last_height || telemetry.height || 0)}
                    Wallet State: {infoOk ? 'Connected' : 'Disconnected'}
                    Wallet Health: {walletHealthQ.data?.ok ? String(walletHealth.status || 'ok') : `error: ${walletHealthQ.data?.error || 'unavailable'}`}
                    Wallet Error: {infoOk ? 'None' : (runtimeWalletd.lastInfoError || runtimeWalletd.lastSyncError || 'unavailable')}
                    Selected Mining Address: {selectedMinerAddress ? safeShortAddress(selectedMinerAddress) : 'Default (#0)'}
                  </pre>
                </article>
              </section>

              <section className="card panel">
                <h3>Fibonacci Wall</h3>
                <pre className="mono-box">
                  {fibQ.data?.ok && Array.isArray(fibQ.data.result) && fibQ.data.result.length
                    ? fibQ.data.result
                      .slice(0, 24)
                      .map((x, i) => `#${i + 1}  h=${x.block_height ?? '?'}  owner=${safeShortAddress(x.proposer || x.owner || x.address || 'unknown')}`)
                      .join('\n')
                    : `Unavailable: ${fibQ.data?.error || 'no entries yet'}`}
                </pre>
              </section>
            </>
          )}

          {view === 'mining' && (
            <section className="grid two">
              <article className="card panel">
                <h3>Mining Configuration</h3>
                <Tabs.Root value={miningMode} onValueChange={setMiningMode}>
                  <Tabs.List className="mode-tabs">
                    <Tabs.Trigger value="cpu">CPU Only</Tabs.Trigger>
                    <Tabs.Trigger value="gpu">GPU Only</Tabs.Trigger>
                    <Tabs.Trigger value="hybrid">Hybrid</Tabs.Trigger>
                  </Tabs.List>
                </Tabs.Root>

                <div className="slider-wrap">
                  <label>Backend Engine</label>
                  <select
                    value={miningBackend}
                    onChange={(e) => {
                      setMiningBackend(String(e.target.value || 'auto').toLowerCase());
                      setMiningPreset('custom');
                    }}
                  >
                    {availableBackends.map((backend) => (
                      <option key={backend} value={backend}>
                        {backend.toUpperCase()}
                      </option>
                    ))}
                  </select>
                  <label>OpenCL Device ID <b>{gpuDeviceId}</b></label>
                  <Slider.Root className="slider" max={8} min={0} step={1} value={[gpuDeviceId]} onValueChange={(v) => { setGpuDeviceId(v[0] || 0); setMiningPreset('custom'); }}>
                    <Slider.Track className="slider-track"><Slider.Range className="slider-range" /></Slider.Track>
                    <Slider.Thumb className="slider-thumb" />
                  </Slider.Root>
                  <label>CUDA Device Ordinal <b>{cudaDeviceOrdinal}</b></label>
                  <Slider.Root className="slider" max={8} min={0} step={1} value={[cudaDeviceOrdinal]} onValueChange={(v) => { setCudaDeviceOrdinal(v[0] || 0); setMiningPreset('custom'); }}>
                    <Slider.Track className="slider-track"><Slider.Range className="slider-range" /></Slider.Track>
                    <Slider.Thumb className="slider-thumb" />
                  </Slider.Root>
                  <small className="hint">Auto backend picks CUDA, then OpenCL, then CPU fallback.</small>
                </div>

                <div className="preset-row">
                  <button className={`preset preset-max ${miningPreset === 'maximum' ? 'active' : ''}`} onClick={() => applyPreset('maximum')}>Maximum</button>
                  <button className={`preset preset-balanced ${miningPreset === 'balanced' ? 'active' : ''}`} onClick={() => applyPreset('balanced')}>Balanced</button>
                  <button className={`preset preset-eco ${miningPreset === 'eco' ? 'active' : ''}`} onClick={() => applyPreset('eco')}>Eco</button>
                  <button className={`preset preset-gaming ${miningPreset === 'gaming' ? 'active' : ''}`} onClick={() => applyPreset('gaming')}>Gaming</button>
                  <button className={`preset preset-custom ${miningPreset === 'custom' ? 'active' : ''}`} onClick={() => applyPreset('custom')}>Custom</button>
                </div>

                <div className="slider-wrap">
                  <label>CPU Cores <b>{sliders.cpuCores}</b></label>
                  <Slider.Root className="slider" max={32} min={1} step={1} value={[sliders.cpuCores]} onValueChange={(v) => setSliderAndMarkCustom('cpuCores', v[0] || 1)}>
                    <Slider.Track className="slider-track"><Slider.Range className="slider-range" /></Slider.Track>
                    <Slider.Thumb className="slider-thumb" />
                  </Slider.Root>

                  <label>CPU Utilization <b>{sliders.cpuUtil}%</b></label>
                  <Slider.Root className="slider" max={100} min={1} step={1} value={[sliders.cpuUtil]} onValueChange={(v) => setSliderAndMarkCustom('cpuUtil', v[0] || 1)}>
                    <Slider.Track className="slider-track"><Slider.Range className="slider-range" /></Slider.Track>
                    <Slider.Thumb className="slider-thumb" />
                  </Slider.Root>

                  <label>GPU Utilization <b>{sliders.gpuUtil}%</b></label>
                  <Slider.Root className="slider" max={100} min={1} step={1} value={[sliders.gpuUtil]} onValueChange={(v) => setSliderAndMarkCustom('gpuUtil', v[0] || 1)}>
                    <Slider.Track className="slider-track"><Slider.Range className="slider-range" /></Slider.Track>
                    <Slider.Thumb className="slider-thumb" />
                  </Slider.Root>

                  <label>VRAM Allocation <b>{sliders.vram}%</b></label>
                  <Slider.Root className="slider" max={100} min={1} step={1} value={[sliders.vram]} onValueChange={(v) => setSliderAndMarkCustom('vram', v[0] || 1)}>
                    <Slider.Track className="slider-track"><Slider.Range className="slider-range" /></Slider.Track>
                    <Slider.Thumb className="slider-thumb" />
                  </Slider.Root>
                </div>

                <div className="action-grid compact">
                  <button disabled={Boolean(busyAction)} onClick={() => act('Start Mining', () => window.knox.startNode(true, miningProfileFromUi()))}>
                    {busyAction === 'Start Mining' ? 'Start Mining...' : 'Start Mining'}
                  </button>
                  <button className="action-danger" disabled={Boolean(busyAction)} onClick={() => act('Stop Mining', () => window.knox.stopService('node'))}>
                    {busyAction === 'Stop Mining' ? 'Stop Mining...' : 'Stop Mining'}
                  </button>
                  <button disabled={Boolean(busyAction)} onClick={() => act('Start Wallet', () => window.knox.startWalletd())}>
                    {busyAction === 'Start Wallet' ? 'Start Wallet...' : 'Start Wallet'}
                  </button>
                  <button disabled={Boolean(busyAction)} onClick={() => act('Sync Wallet', () => window.knox.walletSync())}>
                    {busyAction === 'Sync Wallet' ? 'Sync Wallet...' : 'Sync Wallet'}
                  </button>
                  <button disabled={Boolean(busyAction)} onClick={() => act('Apply Changes', async () => {
                    const saved = await saveMiningConfig();
                    if (!saved?.ok) return saved;
                    return window.knox.miningApplyLive(miningProfileFromUi());
                  })}>
                    {busyAction === 'Apply Changes' ? 'Apply Changes...' : 'Apply Changes'}
                  </button>
                </div>
                <div className="action-status">{actionStatus}</div>
              </article>

              <article className="card panel">
                <h3>Mining Telemetry</h3>
                <div className="mini-grid">
                  <div><span>Chain Height</span><b>{numOrNa(telemetry.height)}</b></div>
                  <div><span>Difficulty</span><b>{telemetry.difficulty ? telemetry.difficulty.toFixed(6) : 'N/A'}</b></div>
                  <div><span>Total Hardening</span><b>{numOrNa(telemetry.hardening)}</b></div>
                  <div><span>Active Miners</span><b>{numOrNa(telemetry.miners)}</b></div>
                  <div><span>Streak</span><b>{numOrNa(telemetry.streak)}</b></div>
                  <div><span>Streak Bonus</span><b>{numOrNa(telemetry.bonus)}</b></div>
                  <div><span>Configured Backend</span><b>{configuredBackendLabel}</b></div>
                  <div><span>Active Backend</span><b>{activeBackendLabel}</b></div>
                  <div><span>Backend Device</span><b>{String(runtimeNode.activeDevice || 'cpu-main')}</b></div>
                  <div><span>Data Source</span><b>{netQ.data?.ok ? 'Network' : (runtimeNode.running ? 'Local Node' : 'N/A')}</b></div>
                  <div><span>Last Sealed</span><b>{Number.isFinite(Number(runtimeNode.lastSealedHeight)) ? `#${runtimeNode.lastSealedHeight}` : 'N/A'}</b></div>
                </div>
                {(runtimeFallback || runtimeBackendError) && (
                  <pre className="mono-box">Fallback: {runtimeFallback ? 'ACTIVE' : 'OFF'}{runtimeBackendError ? `\nReason: ${runtimeBackendError}` : ''}</pre>
                )}
                <h3 className="subhead">Current Performance</h3>
                <div className="mini-grid">
                  <div><span>Hashrate</span><b>{performance.hashRate.toLocaleString()} H/s</b></div>
                  <div><span>Est. Power</span><b>{performance.power} W</b></div>
                  <div><span>Cost / Day</span><b>${performance.costDay.toFixed(2)}</b></div>
                  <div><span>KNOX / Day</span><b>{performance.knoxDay}</b></div>
                </div>
                <h3 className="subhead">Automation</h3>
                <div className="mini-grid">
                  <div>
                    <span>Schedule Presets</span>
                    <b>{advanced.scheduleEnabled ? 'On' : 'Off'}</b>
                  </div>
                  <div>
                    <span>Surge Auto-Max</span>
                    <b>{advanced.surgeAutoMax ? 'On' : 'Off'}</b>
                  </div>
                  <div>
                    <span>Temp Throttle</span>
                    <b>{advanced.tempThrottle ? 'On' : 'Off'}</b>
                  </div>
                  <div>
                    <span>$/kWh</span>
                    <b>{Number(advanced.powerCostPerKwh || 0.12).toFixed(2)}</b>
                  </div>
                </div>
                <div className="action-grid compact">
                  <button onClick={() => setAdvanced((a) => ({ ...a, scheduleEnabled: !a.scheduleEnabled }))}>
                    {advanced.scheduleEnabled ? 'Disable Schedule' : 'Enable Schedule'}
                  </button>
                  <button onClick={() => setAdvanced((a) => ({ ...a, surgeAutoMax: !a.surgeAutoMax }))}>
                    {advanced.surgeAutoMax ? 'Disable Surge Auto-Max' : 'Enable Surge Auto-Max'}
                  </button>
                  <button onClick={() => setAdvanced((a) => ({ ...a, tempThrottle: !a.tempThrottle }))}>
                    {advanced.tempThrottle ? 'Disable Temp Throttle' : 'Enable Temp Throttle'}
                  </button>
                  <button onClick={() => setAdvanced((a) => ({ ...a, powerCostPerKwh: Math.max(0.01, Number((a.powerCostPerKwh + 0.01).toFixed(2))) }))}>
                    Increase $/kWh
                  </button>
                </div>
              </article>
            </section>
          )}

          {view === 'send' && (
            <section className="grid two">
              <article className="card panel form-card">
                <h3>Send KNOX</h3>
                <label>Recipient Address</label>
                <input value={sendForm.to} onChange={(e) => setSendForm((s) => ({ ...s, to: e.target.value }))} placeholder="KNOX1..." />
                <div className="action-grid compact">
                  <button onClick={() => setScanQrOpen(true)}>
                    Scan QR
                  </button>
                  {scanQrOpen && (
                    <button className="action-danger" onClick={() => setScanQrOpen(false)}>
                      Stop Scan
                    </button>
                  )}
                </div>
                {scanQrOpen && (
                  <div className="panel" style={{ marginTop: 8 }}>
                    <video
                      ref={scanVideoRef}
                      autoPlay
                      muted
                      playsInline
                      style={{ width: '100%', borderRadius: 10, background: '#020612' }}
                    />
                    <small className="hint">Point camera at a QR code containing a `knox1...` address.</small>
                  </div>
                )}
                {scanQrError && <pre className="mono-box">{scanQrError}</pre>}
                <label>Amount</label>
                <input value={sendForm.amount} onChange={(e) => setSendForm((s) => ({ ...s, amount: e.target.value }))} />
                <div className="grid two">
                  <div>
                    <label>Fee</label>
                    <input value={sendForm.fee} onChange={(e) => setSendForm((s) => ({ ...s, fee: e.target.value }))} />
                  </div>
                  <div>
                    <label>Ring Size</label>
                    <input value={sendForm.ring} onChange={(e) => setSendForm((s) => ({ ...s, ring: e.target.value }))} />
                  </div>
                </div>
                <button disabled={Boolean(busyAction)} onClick={() => act('Send Transaction', () => {
                  const to = sendForm.to.trim();
                  if (!/^knox1[a-f0-9]{32,}$/i.test(to)) {
                    return { ok: false, error: 'Recipient address is invalid' };
                  }
                  const amount = parseNumericField(sendForm.amount, 'Amount', { min: 0, minInclusive: false });
                  if (!amount.ok) return amount;
                  const fee = parseNumericField(sendForm.fee, 'Fee', { min: 0, minInclusive: true });
                  if (!fee.ok) return fee;
                  const ring = parseNumericField(sendForm.ring, 'Ring size', { integer: true, min: 2, minInclusive: true });
                  if (!ring.ok) return ring;
                  const confirmText = `Send ${amount.value} KNOX to ${safeShortAddress(to)} with fee ${fee.value} and ring ${ring.value}?`;
                  if (!globalThis.confirm(confirmText)) {
                    return { ok: false, error: 'Send cancelled' };
                  }
                  return window.knox.walletdSend({
                    to,
                    amount: amount.value,
                    fee: fee.value,
                    ring: ring.value
                  });
                })}>{busyAction === 'Send Transaction' ? 'Send Transaction...' : 'Send Transaction'}</button>
              </article>

              <article className="card panel">
                <h3>Addresses</h3>
                <div className="address-list">
                  {!indexedAddresses.length && <div className="address-item">No addresses yet</div>}
                  {indexedAddresses.map((entry, i) => (
                    <div className={`address-item ${selectedMinerAddress === entry.address ? 'selected' : ''}`} key={`${entry.address}-${entry.index}-${i}`}>
                      <div className="idx">#{entry.index}</div>
                      <div className="addr" title={entry.address}>{safeShortAddress(entry.address)}</div>
                      <div className="bal">{entry.index === 0 ? `${fmtAtoms(info.balance)} KNOX` : '-'}</div>
                      <button
                        className="mini-btn"
                        onClick={() => copyAddressToClipboard(entry.address)}
                      >
                        Copy
                      </button>
                      <button
                        className={`mini-btn ${selectedMinerAddress === entry.address ? 'mini-btn-active' : ''}`}
                        disabled={Boolean(busyAction)}
                        onClick={() => act('Select Mining Address', async () => {
                          const out = await window.knox.minerAddressSet(entry.address);
                          if (out?.ok) setSelectedMinerAddressLive(entry.address);
                          return out;
                        })}
                      >
                        {selectedMinerAddress === entry.address ? 'Mining Target' : 'Mine To This'}
                      </button>
                    </div>
                  ))}
                </div>
              </article>
            </section>
          )}

          {view === 'logs' && (
            <section className="card panel logs-panel">
              <h3>Logs</h3>
              <pre className="log-box">{logLines.join('\n')}</pre>
            </section>
          )}

          {view === 'settings' && (
            <section className="grid two">
              <article className="card panel">
                <h3>Theme</h3>
                <label>Glow Intensity <b>{glow}%</b></label>
                <Slider.Root className="slider" max={100} min={0} step={1} value={[glow]} onValueChange={(v) => setGlow(v[0] || 0)}>
                  <Slider.Track className="slider-track"><Slider.Range className="slider-range" /></Slider.Track>
                  <Slider.Thumb className="slider-thumb" />
                </Slider.Root>
              </article>

              <article className="card panel">
                <h3>Wallet Tools</h3>
                <div className="mini-grid">
                  <div><span>Wallet Health</span><b>{walletHealthQ.data?.ok ? String(walletHealth.status || 'ok') : 'Error'}</b></div>
                  <div><span>Indexed Addresses</span><b>{indexedAddresses.length}</b></div>
                </div>
                <div className="action-grid compact">
                  <button onClick={() => setShowDebugWalletTools((v) => !v)}>
                    {showDebugWalletTools ? 'Hide Debug Wallet Tools' : 'Reveal Debug Wallet Tools'}
                  </button>
                  <button
                    disabled={Boolean(busyAction)}
                    onClick={() => act('Reinstall / Update App', () => window.knox.launchInstaller())}
                  >
                    {busyAction === 'Reinstall / Update App' ? 'Reinstall / Update App...' : 'Reinstall / Update App'}
                  </button>
                  <button
                    disabled={Boolean(busyAction)}
                    onClick={() => act('Wallet Health', () => window.knox.walletdHealth())}
                  >
                    {busyAction === 'Wallet Health' ? 'Wallet Health...' : 'Wallet Health'}
                  </button>
                  <button
                    disabled={Boolean(busyAction)}
                    onClick={() => act('Wallet Addresses', () => window.knox.walletdAddresses())}
                  >
                    {busyAction === 'Wallet Addresses' ? 'Wallet Addresses...' : 'Wallet Addresses'}
                  </button>
                </div>
                {showDebugWalletTools && (
                  <>
                    <label>Node Key Path</label>
                    <input
                      value={importNodeKeyPath}
                      onChange={(e) => setImportNodeKeyPath(e.target.value)}
                      placeholder="C:\\path\\to\\node.key"
                    />
                    <div className="action-grid compact">
                      <button
                        disabled={Boolean(busyAction)}
                        onClick={() => act('Import Node Key', async () => {
                          const pathText = String(importNodeKeyPath || '').trim();
                          if (!pathText) return { ok: false, error: 'Node key path is required' };
                          const confirmed = globalThis.confirm(`Import node key from ${pathText}? This replaces wallet keys.`);
                          if (!confirmed) return { ok: false, error: 'Import cancelled' };
                          return window.knox.walletImportNodeKey(pathText);
                        })}
                      >
                        {busyAction === 'Import Node Key' ? 'Import Node Key...' : 'Import Node Key'}
                      </button>
                      <button
                        disabled={Boolean(busyAction)}
                        onClick={() => act('Rescan Wallet', () => window.knox.walletRescan())}
                      >
                        {busyAction === 'Rescan Wallet' ? 'Rescan Wallet...' : 'Rescan Wallet'}
                      </button>
                    </div>
                    <pre className="mono-box">
                      {walletAddrIndexedQ.data?.ok
                        ? indexedAddresses.slice(0, 24).map((entry) => `#${entry.index}: ${entry.address}`).join('\n')
                        : (indexedAddresses.length
                          ? indexedAddresses.slice(0, 24).map((entry) => `#${entry.index}: ${entry.address}`).join('\n')
                          : `Address query unavailable. Wallet service may be offline.`)}
                    </pre>
                  </>
                )}
              </article>
            </section>
          )}
        </main>
      </ErrorBoundary>
    </div>
  );
}
