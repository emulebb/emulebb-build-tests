"""Import stock/MFC hashes offline using one TOML job."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from emule_test_harness.profile_import_job import main

if __name__ == "__main__":
    raise SystemExit(main())
