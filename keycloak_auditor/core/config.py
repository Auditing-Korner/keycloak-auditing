from pydantic import BaseModel


class AuditorConfig(BaseModel):
	base_url: str
	realm: str = "master"
	client_id: str | None = None
	client_secret: str | None = None
	token: str | None = None
	nuclei_path: str = "nuclei"
	nuclei_templates: str = "nuclei-templates"
	output_dir: str = "audit-output"
