import subprocess
import sys


def test_cli_help():
	proc = subprocess.run([sys.executable, "-m", "keycloak_auditor.cli", "--help"], capture_output=True, text=True)
	assert proc.returncode == 0
	assert "Keycloak Auditor CLI" in proc.stdout
