#!/usr/bin/env python3
"""Copy and observe an explicitly approved Android upload-only public campaign."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emule_test_harness.android_public_sharing import main

if __name__ == "__main__":
    raise SystemExit(main())
