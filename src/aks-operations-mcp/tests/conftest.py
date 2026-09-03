import sys
from pathlib import Path

# Tool modules import as `tools.<name>`, so the server root must be on sys.path.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
