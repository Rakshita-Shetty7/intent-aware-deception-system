"""
Vercel Serverless Function Entrypoint.
Exposes the FastAPI application for Vercel Python runtime.
"""

import os
import sys
from pathlib import Path

# Ensure project root directory is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from backend.app.main import app
