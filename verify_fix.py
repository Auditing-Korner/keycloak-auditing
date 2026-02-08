import json
import os
from pathlib import Path
from unittest.mock import MagicMock
from keycloak_auditor.report.html_generator import HTMLReportGenerator

def test_html_fix():
    print("Testing HTML Report Generator fix...")
    
    # Mock config
    config = MagicMock()
    config.base_url = "https://kc.example.com"
    config.realm = "master"
    config.output_dir = "audit-output"
    
    # Create output dir
    os.makedirs(config.output_dir, exist_ok=True)
    
    # Mock data files
    (Path(config.output_dir) / "enumeration.json").write_text(json.dumps({"server_version": "20.0.1"}))
    (Path(config.output_dir) / "audit.json").write_text(json.dumps([]))
    (Path(config.output_dir) / "nuclei.json").write_text(json.dumps([]))
    (Path(config.output_dir) / "exploitation.json").write_text(json.dumps([]))
    
    # Run generator
    generator = HTMLReportGenerator(config)
    report_path = generator.generate()
    
    content = Path(report_path).read_text()
    
    # Check if Jinja2 tags are resolved
    if "{{ base_url }}" in content:
        print("FAIL: Jinja2 tag {{ base_url }} found in output!")
        return False
    
    if "https://kc.example.com" in content:
        print("SUCCESS: HTML contains injected value 'https://kc.example.com'")
    else:
        print("FAIL: HTML does not contain injected value 'https://kc.example.com'")
        return False
        
    # Check Phase 2: CVE Mapping (real data)
    if "CVE-2022-1245" in content:
        print("SUCCESS: HTML contains real Keycloak CVE 'CVE-2022-1245'")
    else:
        print("FAIL: HTML does not contain real Keycloak CVE 'CVE-2022-1245'")
        return False

    # Check Phase 2: Compliance Mapping
    if "CIS-1.1" in content:
        print("SUCCESS: HTML contains compliance mapping 'CIS-1.1'")
    else:
        print("FAIL: HTML does not contain compliance mapping 'CIS-1.1'")
        return False
        
    print(f"Report generated at: {report_path}")
    return True

if __name__ == "__main__":
    if test_html_fix():
        print("All checks passed!")
    else:
        print("Checks failed!")
