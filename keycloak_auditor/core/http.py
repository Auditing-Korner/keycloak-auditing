import time
from typing import Any, Dict, Optional

import requests

from .config import AuditorConfig


class ThrottledRequester:
	def __init__(self, config: AuditorConfig):
		self.config = config
		self._min_interval = 1.0 / max(self.config.rate_limit_rps, 0.1)
		self._last_request_ts = 0.0

	def _sleep_if_needed(self) -> None:
		now = time.time()
		elapsed = now - self._last_request_ts
		if elapsed < self._min_interval:
			time.sleep(self._min_interval - elapsed)
		self._last_request_ts = time.time()

	def request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
		attempts = max(self.config.retries + 1, 1)
		for attempt in range(attempts):
			self._sleep_if_needed()
			try:
				resp = requests.request(
					method,
					url,
					timeout=self.config.http_timeout_seconds,
					verify=self.config.verify_ssl,
					**kwargs,
				)
				return resp
			except requests.RequestException:
				if attempt == attempts - 1:
					raise
				time.sleep(self.config.backoff_seconds)
		return requests.Response()  # unreachable, satisfies type checkers
