from abc import ABC, abstractmethod
from typing import Any, Dict, List

from ..core.config import AuditorConfig
from ..core.http import ThrottledRequester


class BasePlugin(ABC):
	"""Base class for Keycloak Auditor plugins."""
	
	def __init__(self, config: AuditorConfig):
		self.config = config
		self.http = ThrottledRequester(config)
	
	@abstractmethod
	def get_name(self) -> str:
		"""Return the plugin name."""
		pass
	
	@abstractmethod
	def get_version(self) -> str:
		"""Return the plugin version."""
		pass
	
	@abstractmethod
	def get_description(self) -> str:
		"""Return the plugin description."""
		pass
	
	@abstractmethod
	def run(self) -> List[Dict[str, Any]]:
		"""Run the plugin and return findings."""
		pass


class EnumerationPlugin(BasePlugin):
	"""Base class for enumeration plugins."""
	
	@abstractmethod
	def enumerate(self) -> Dict[str, Any]:
		"""Perform enumeration and return results."""
		pass
	
	def run(self) -> List[Dict[str, Any]]:
		"""Run enumeration plugin."""
		try:
			results = self.enumerate()
			return [{
				"id": f"{self.get_name()}_enumeration",
				"title": f"Enumeration results from {self.get_name()}",
				"severity": "info",
				"data": results
			}]
		except Exception as e:
			return [{
				"id": f"{self.get_name()}_error",
				"title": f"Error in {self.get_name()} enumeration",
				"severity": "info",
				"error": str(e)
			}]


class AuditPlugin(BasePlugin):
	"""Base class for audit plugins."""
	
	@abstractmethod
	def audit(self) -> List[Dict[str, Any]]:
		"""Perform audit checks and return findings."""
		pass
	
	def run(self) -> List[Dict[str, Any]]:
		"""Run audit plugin."""
		try:
			return self.audit()
		except Exception as e:
			return [{
				"id": f"{self.get_name()}_error",
				"title": f"Error in {self.get_name()} audit",
				"severity": "info",
				"error": str(e)
			}]


class ExploitationPlugin(BasePlugin):
	"""Base class for exploitation plugins."""
	
	@abstractmethod
	def exploit(self) -> List[Dict[str, Any]]:
		"""Perform safe exploitation and return results."""
		pass
	
	def run(self) -> List[Dict[str, Any]]:
		"""Run exploitation plugin."""
		try:
			return self.exploit()
		except Exception as e:
			return [{
				"id": f"{self.get_name()}_error",
				"title": f"Error in {self.get_name()} exploitation",
				"severity": "info",
				"error": str(e)
			}]
