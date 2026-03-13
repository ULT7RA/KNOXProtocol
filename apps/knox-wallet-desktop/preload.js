const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('knox', {
  quickStart: (profile) => ipcRenderer.invoke('quick-start', profile),
  startNode: (mine, profile) => ipcRenderer.invoke('start-node', mine, profile),
  startWalletd: () => ipcRenderer.invoke('start-walletd'),
  stopService: (name) => ipcRenderer.invoke('stop-service', name),
  serviceState: () => ipcRenderer.invoke('service-state'),
  onboardingState: () => ipcRenderer.invoke('onboarding-state'),
  nodeRuntimeStats: () => ipcRenderer.invoke('node-runtime-stats'),
  walletCreate: () => ipcRenderer.invoke('wallet-create'),
  walletAddress: () => ipcRenderer.invoke('wallet-address'),
  walletAddresses: () => ipcRenderer.invoke('wallet-addresses'),
  minerAddressGet: () => ipcRenderer.invoke('miner-address-get'),
  minerAddressSet: (addr) => ipcRenderer.invoke('miner-address-set', addr),
  walletNewAddress: () => ipcRenderer.invoke('wallet-new-address'),
  walletBalance: () => ipcRenderer.invoke('wallet-balance'),
  walletSync: () => ipcRenderer.invoke('wallet-sync'),
  walletRescan: () => ipcRenderer.invoke('wallet-rescan'),
  walletImportNodeKey: (nodeKeyPath) => ipcRenderer.invoke('wallet-import-node-key', nodeKeyPath),
  walletBackupsList: (limit) => ipcRenderer.invoke('wallet-backups-list', limit),
  walletBackupRestoreLatest: () => ipcRenderer.invoke('wallet-backup-restore-latest'),
  walletBackupRestore: (backupPath) => ipcRenderer.invoke('wallet-backup-restore', backupPath),
  walletdHealth: () => ipcRenderer.invoke('walletd-health'),
  walletdAddresses: () => ipcRenderer.invoke('walletd-addresses'),
  walletdInfo: () => ipcRenderer.invoke('walletd-info'),
  walletdSend: (payload) => ipcRenderer.invoke('walletd-send', payload),
  walletdNetwork: () => ipcRenderer.invoke('walletd-network'),
  walletdFibWall: (limit) => ipcRenderer.invoke('walletd-fib-wall', limit),
  launchInstaller: () => ipcRenderer.invoke('launch-installer'),
  tlsGenerate: () => ipcRenderer.invoke('tls-generate'),
  miningBackends: () => ipcRenderer.invoke('mining-backends'),
  miningRuntime: () => ipcRenderer.invoke('mining-runtime'),
  miningConfigGet: () => ipcRenderer.invoke('mining-config-get'),
  miningConfigSet: (cfg) => ipcRenderer.invoke('mining-config-set', cfg),
  miningApplyLive: (profile) => ipcRenderer.invoke('mining-apply-live', profile),
  onLog: (cb) => {
    const handler = (_event, message) => cb(message);
    ipcRenderer.on('log', handler);
    return () => ipcRenderer.removeListener('log', handler);
  },
  onWalletUpdated: (cb) => {
    const handler = (_event, payload) => cb(payload || {});
    ipcRenderer.on('wallet-updated', handler);
    return () => ipcRenderer.removeListener('wallet-updated', handler);
  }
});
