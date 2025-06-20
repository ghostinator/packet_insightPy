#!/bin/bash
# Packet Insight Builder

# Create build directory
mkdir -p build
cd build

# Create spec file
cat > packet_insight.spec <<EOL
# -*- mode: python ; coding: utf-8 -*-
block_cipher = None
a = Analysis(
    ['../packet_insight.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('../packet_utils.py', '.'),
        ('../baseline_manager.py', '.'),
        ('../live_capture.py', '.')
    ],
    hiddenimports=['pyshark', 'tqdm', 'json', 'argparse', 'subprocess', 'os', 'sys', 'time', 'platform', 'collections', 'datetime'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='PacketInsight',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
EOL

# Build executable
pyinstaller packet_insight.spec

echo "Build complete! Executable is in build/dist"
