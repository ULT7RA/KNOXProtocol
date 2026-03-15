# Docker Images (Linux)

This folder provides two Linux container images:

- `knox/node:linux` for headless node participation
- `knox/gui:linux` for the desktop wallet GUI on Linux X11 hosts

## Build

From repo root:

```bash
docker build -f docker/Dockerfile.node -t knox/node:linux .
docker build -f docker/Dockerfile.gui -t knox/gui:linux .
```

## Run Node Container

The entrypoint auto-connects to all 6 ForgeTitan seed peers. Override `KNOX_NODE_PEERS` to
customize. Mining is **off** by default (`KNOX_NODE_NO_MINE=1`); set it to `0` to mine.

```bash
docker run -d --name knox-node \
  -p 9735:9735 -p 9736:9736 \
  -e KNOX_NODE_RPC_ALLOW_REMOTE=1 \
  -e KNOX_NODE_NO_MINE=0 \
  -e KNOX_NODE_MINER_ADDRESS="<your_knox1_address>" \
  -v knox-node-data:/var/lib/knox/node \
  knox/node:linux
```

## Run GUI Container (X11)

Allow the local container user to connect to your display:

```bash
xhost +local:
```

Start GUI:

```bash
docker run --rm --name knox-gui \
  -e DISPLAY=$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix:rw \
  -v knox-gui-data:/home/knox/.config/knox-wallet-desktop \
  knox/gui:linux
```

If your kernel blocks Chromium sandbox namespaces, retry with:

```bash
docker run --rm --name knox-gui \
  -e DISPLAY=$DISPLAY \
  -e KNOX_ELECTRON_NO_SANDBOX=1 \
  -v /tmp/.X11-unix:/tmp/.X11-unix:rw \
  -v knox-gui-data:/home/knox/.config/knox-wallet-desktop \
  knox/gui:linux
```

## Docker Compose

```bash
docker compose -f docker/docker-compose.linux.yml up --build -d
```

Set optional env vars first if needed:

- `KNOX_NODE_MINER_ADDRESS`
- `KNOX_NODE_PEERS`
- `KNOX_ELECTRON_NO_SANDBOX`

## Notes

- Runtime contents are intentionally minimal:
  - `knox/node:linux`: `knox-node` binary + entrypoint + runtime libs only.
  - `knox/gui:linux`: Electron runtime + `main.js`/`preload.js`/built renderer/assets + `node_modules` + three Rust binaries.
  - No wallet backups, no local VM state, no `launch-mainnet`, no `keys-live`, no anti-compact memory docs.
- The GUI image embeds Linux-built Rust binaries in `apps/knox-wallet-desktop/bin` with `.exe` filenames to match current desktop launcher expectations.
- Node chain state is persisted in volume `knox-node-data`.
- GUI wallet state is persisted in volume `knox-gui-data`.
- `.dockerignore` excludes sensitive and large local artifacts (keys, launch data, wallet backups, build outputs) from build context.
