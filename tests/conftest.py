import sys
from pathlib import Path

# Make `secure_headers` importable when running `pytest` from the project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
