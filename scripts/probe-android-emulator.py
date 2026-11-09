#!/usr/bin/env python3
"""Prove one pinned Android guest boot without claiming APK or ChromeOS support."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emule_test_harness.android_emulator import probe_guest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--image-dir", type=Path, required=True)
    parser.add_argument("--api", type=int, required=True)
    parser.add_argument("--page-size", type=int, choices=(4096, 16384), required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--report-dir", type=Path, required=True)
    arguments = parser.parse_args()
    print(probe_guest(**vars(arguments)))


if __name__ == "__main__":
    main()
