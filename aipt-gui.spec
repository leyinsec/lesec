# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['aipt_gui_entry.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('aipt/core/*.py', 'aipt/core'),
        ('aipt/scanners/*.py', 'aipt/scanners'),
        ('aipt/*.py', 'aipt'),
    ],
    hiddenimports=[
        'aipt.core.config',
        'aipt.core.engine',
        'aipt.core.models',
        'aipt.core.async_engine',
        'aipt.core.ai_detector',
        'aipt.core.auth_manager',
        'aipt.core.report_generator',
        'aipt.scanners.vulnerability_scanner',
        'aipt.scanners.js_auditor',
        'aiohttp',
        'aiofiles',
        'bs4',
        'lxml',
        'jinja2',
        'yaml',
        'sklearn',
        'sklearn.ensemble',
        'numpy',
        'cryptography',
        'jwt',
        'async_timeout',
        'aiosignal',
        'frozenlist',
        'multidict',
        'yarl',
        'charset_normalizer',
    ],
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
    name='aipt-gui',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # No console window for GUI
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
