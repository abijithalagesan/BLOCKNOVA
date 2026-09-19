import json
import subprocess
import sys
from pathlib import Path


def test_analyzer_cli_outputs_json():
    root = Path(__file__).parents[1]
    completed = subprocess.run([sys.executable, "-m", "analyzer", "0x1111111111111111111111111111111111111111"], cwd=root, check=True, capture_output=True, text=True)
    output = json.loads(completed.stdout)
    assert output["address"] == "0x1111111111111111111111111111111111111111"
    assert "riskVector" in output
    assert output["topEvidence"]
