# Make app icons from your PNG

## Automatic (preferred)

`apps/knox-wallet-desktop` now auto-generates
`apps/knox-wallet-desktop/assets/icon.ico` before packaging (`npm run dist` / `npm run build`).
It picks the first existing source PNG in this order:

1. `apps/knox-wallet-desktop/assets/icon-source.png`
2. `apps/knox-wallet-desktop/assets/icon.png`
3. `apps/knox-wallet-desktop/assets/knoc.png`

If you want to swap branding, place your image at
`apps/knox-wallet-desktop/assets/icon-source.png` and run:

```
npm --prefix apps/knox-wallet-desktop run build
```

Save your provided logo as:

```
apps/knox-wallet-desktop/assets/icon-source.png
```

## Option A: ImageMagick (recommended)

Windows PowerShell:

```
magick convert apps/knox-wallet-desktop/assets/icon-source.png -resize 256x256 -background none -gravity center -extent 256x256 apps/knox-wallet-desktop/assets/icon.ico
magick convert apps/knox-wallet-desktop/assets/icon-source.png -resize 1024x1024 -background none -gravity center -extent 1024x1024 apps/knox-wallet-desktop/assets/icon.icns
```

Linux:

```
magick convert apps/knox-wallet-desktop/assets/icon-source.png -resize 256x256 -background none -gravity center -extent 256x256 apps/knox-wallet-desktop/assets/icon.ico
magick convert apps/knox-wallet-desktop/assets/icon-source.png -resize 1024x1024 -background none -gravity center -extent 1024x1024 apps/knox-wallet-desktop/assets/icon.icns
```

## Option B: Python + Pillow

```
python -m pip install pillow
python - <<'PY'
from PIL import Image
from pathlib import Path
src = Path('apps/knox-wallet-desktop/assets/icon-source.png')
img = Image.open(src).convert('RGBA')
img.save('apps/knox-wallet-desktop/assets/icon.ico', sizes=[(256,256)])
img.save('apps/knox-wallet-desktop/assets/icon.icns')
PY
```

## Linux icon set

```
mkdir -p apps/knox-wallet-desktop/build/icons
for size in 16 32 48 64 128 256 512 1024; do
  magick convert apps/knox-wallet-desktop/assets/icon-source.png -resize ${size}x${size} apps/knox-wallet-desktop/build/icons/icon_${size}.png
Done
```
