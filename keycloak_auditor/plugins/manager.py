import importlib
import inspect
import sys
from pathlib import Path
from typing import Any, Dict, List, Type

from .base import BasePlugin, EnumerationPlugin, AuditPlugin, ExploitationPlugin


class PluginManager:
	"""Manages loading and execution of plugins."""
	
	def __init__(self, config):
		self.config = config
		self.plugins_dir = Path(__file__).parent.parent.parent / "plugins"
		self.loaded_plugins: Dict[str, BasePlugin] = {}
	
	def _discover_plugins(self) -> List[Path]:
		"""Discover plugin files in the plugins directory."""
		if not self.plugins_dir.exists():
			return []
		
		plugin_files = []
		for file_path in self.plugins_dir.glob("*.py"):
			if file_path.name != "__init__.py":
				plugin_files.append(file_path)
		
		return plugin_files
	
	def _load_plugin_class(self, plugin_file: Path) -> Type[BasePlugin]:
		"""Load a plugin class from a file."""
		# Ensure we load from the absolute path to avoid shadowing/CWD issues
		module_name = f"plugins.{plugin_file.stem}"
		
		# Add plugins directory's parent to Python path if not already there
		plugins_parent = str(self.plugins_dir.parent.absolute())
		if plugins_parent not in sys.path:
			sys.path.insert(0, plugins_parent)
		
		try:
			module = importlib.import_module(module_name)
			
			# Find plugin classes in the module
			for name, obj in inspect.getmembers(module, inspect.isclass):
				if (issubclass(obj, BasePlugin) and 
					obj != BasePlugin and 
					obj != EnumerationPlugin and 
					obj != AuditPlugin and 
					obj != ExploitationPlugin):
					return obj
			
			raise ImportError(f"No plugin class found in {plugin_file}")
		
		except Exception as e:
			raise ImportError(f"Failed to load plugin {plugin_file}: {e}")
	
	def load_plugins(self) -> Dict[str, BasePlugin]:
		"""Load all available plugins."""
		plugin_files = self._discover_plugins()
		
		for plugin_file in plugin_files:
			try:
				plugin_class = self._load_plugin_class(plugin_file)
				plugin_instance = plugin_class(self.config)
				plugin_name = plugin_instance.get_name()
				self.loaded_plugins[plugin_name] = plugin_instance
				
			except Exception as e:
				print(f"Warning: Failed to load plugin {plugin_file}: {e}")
		
		return self.loaded_plugins
	
	def get_plugins_by_type(self, plugin_type: Type[BasePlugin]) -> List[BasePlugin]:
		"""Get plugins of a specific type."""
		return [
			plugin for plugin in self.loaded_plugins.values()
			if isinstance(plugin, plugin_type)
		]
	
	def run_enumeration_plugins(self) -> List[Dict[str, Any]]:
		"""Run all enumeration plugins."""
		results = []
		enumeration_plugins = self.get_plugins_by_type(EnumerationPlugin)
		
		for plugin in enumeration_plugins:
			try:
				plugin_results = plugin.run()
				results.extend(plugin_results)
			except Exception as e:
				results.append({
					"id": f"{plugin.get_name()}_error",
					"title": f"Error running {plugin.get_name()}",
					"severity": "info",
					"error": str(e)
				})
		
		return results
	
	def run_audit_plugins(self) -> List[Dict[str, Any]]:
		"""Run all audit plugins."""
		results = []
		audit_plugins = self.get_plugins_by_type(AuditPlugin)
		
		for plugin in audit_plugins:
			try:
				plugin_results = plugin.run()
				results.extend(plugin_results)
			except Exception as e:
				results.append({
					"id": f"{plugin.get_name()}_error",
					"title": f"Error running {plugin.get_name()}",
					"severity": "info",
					"error": str(e)
				})
		
		return results
	
	def run_exploitation_plugins(self) -> List[Dict[str, Any]]:
		"""Run all exploitation plugins."""
		results = []
		exploitation_plugins = self.get_plugins_by_type(ExploitationPlugin)
		
		for plugin in exploitation_plugins:
			try:
				plugin_results = plugin.run()
				results.extend(plugin_results)
			except Exception as e:
				results.append({
					"id": f"{plugin.get_name()}_error",
					"title": f"Error running {plugin.get_name()}",
					"severity": "info",
					"error": str(e)
				})
		
		return results
	
	def list_plugins(self) -> List[Dict[str, Any]]:
		"""List all loaded plugins with their information."""
		plugins_info = []
		
		for name, plugin in self.loaded_plugins.items():
			plugins_info.append({
				"name": name,
				"version": plugin.get_version(),
				"description": plugin.get_description(),
				"type": type(plugin).__name__
			})
		
		return plugins_info
