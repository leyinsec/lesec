#!/usr/bin/env python3
"""
AiPT Pro CLI Entry Point
Used by PyInstaller to build the standalone executable.
"""
import sys
import os

# Ensure the aipt package is importable when bundled
if getattr(sys, 'frozen', False):
    # Running in a PyInstaller bundle
    bundle_dir = sys._MEIPASS
    sys.path.insert(0, bundle_dir)
else:
    # Running in normal Python environment
    bundle_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, os.path.dirname(bundle_dir))

from aipt.cli import run

if __name__ == '__main__':
    run()
