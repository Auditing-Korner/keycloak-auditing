from pydantic import BaseModel
from typing import Optional


class AuditorConfig(BaseModel):
	base_url: str
	realm: str = "master"
	client_id: Optional[str] = None
	client_secret: Optional[str] = None
	token: Optional[str] = None
	nuclei_path: str = "nuclei"
	nuclei_templates: str = "nuclei-templates"
	output_dir: str = "audit-output"
	wordlists_dir: str = "wordlists"
	use_wordlists: bool = False
	# HTTP behavior
	rate_limit_rps: float = 5.0
	http_timeout_seconds: int = 15
	retries: int = 2
	backoff_seconds: float = 0.5
	verify_ssl: bool = True
