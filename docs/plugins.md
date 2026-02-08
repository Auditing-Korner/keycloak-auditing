# Plugin System
**Author: RFS**

The Keycloak Auditor framework includes a plugin system that allows you to extend functionality with custom checks, enumeration, and exploitation techniques.

## Plugin Types

### Enumeration Plugins
Extend the enumeration process with custom information gathering.

### Audit Plugins
Add custom security checks and configuration validation.

### Exploitation Plugins
Implement safe exploitation techniques to validate vulnerabilities.

## Creating a Plugin

### 1. Plugin Structure

Create a Python file in the `plugins/` directory:

```python
from keycloak_auditor.plugins.base import AuditPlugin

class MyCustomPlugin(AuditPlugin):
    def get_name(self) -> str:
        return "my-custom-plugin"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_description(self) -> str:
        return "My custom security checks"
    
    def audit(self):
        findings = []
        # Your custom audit logic here
        return findings
```

### 2. Plugin Base Classes

#### BasePlugin
- `get_name()`: Return plugin name
- `get_version()`: Return plugin version
- `get_description()`: Return plugin description
- `run()`: Main execution method

#### EnumerationPlugin
- `enumerate()`: Perform enumeration and return results

#### AuditPlugin
- `audit()`: Perform audit checks and return findings

#### ExploitationPlugin
- `exploit()`: Perform safe exploitation and return results

### 3. Example Plugins

The framework includes example plugins in the `plugins/` directory:

- `example_audit.py`: Custom audit checks
- `example_enumeration.py`: Custom enumeration

## Plugin Management

### List Plugins
```bash
keycloak-auditor --base-url https://kc.example.com --realm master plugins-list
```

### Plugin Integration

Plugins are automatically loaded and executed during the appropriate phases:

- **Enumeration plugins**: Run during the `enumerate` command
- **Audit plugins**: Run during the `audit` command
- **Exploitation plugins**: Run during the `exploit` command

## Plugin Development Guidelines

### 1. Error Handling
Always wrap your plugin logic in try-catch blocks to prevent crashes:

```python
def audit(self):
    findings = []
    try:
        # Your logic here
        pass
    except Exception as e:
        findings.append({
            "id": "plugin_error",
            "title": f"Error in {self.get_name()}",
            "severity": "info",
            "error": str(e)
        })
    return findings
```

### 2. HTTP Requests
Use the provided HTTP client for rate limiting and configuration:

```python
def audit(self):
    findings = []
    try:
        response = self.http.request("GET", f"{self.config.base_url}/custom-endpoint")
        if response.status_code == 200:
            # Process response
            pass
    except Exception:
        pass
    return findings
```

### 3. Finding Format
Return findings in the standard format:

```python
{
    "id": "unique_finding_id",
    "title": "Finding Title",
    "severity": "low|medium|high|critical|info",
    "description": "Detailed description",
    "remediation": "How to fix the issue",
    "evidence": "Supporting evidence"
}
```

### 4. Configuration Access
Access framework configuration through `self.config`:

```python
def audit(self):
    base_url = self.config.base_url
    realm = self.config.realm
    # Use configuration values
```

## Plugin Discovery

The framework automatically discovers plugins by:

1. Scanning the `plugins/` directory for `.py` files
2. Importing each file as a module
3. Finding classes that inherit from plugin base classes
4. Instantiating and registering the plugins

## Best Practices

1. **Keep plugins focused**: Each plugin should have a single responsibility
2. **Use descriptive names**: Make plugin names and descriptions clear
3. **Handle errors gracefully**: Don't let plugin errors crash the framework
4. **Follow the finding format**: Use the standard finding structure
5. **Test your plugins**: Ensure they work correctly before deployment
6. **Document your plugins**: Include clear descriptions and usage instructions

## Plugin Examples

### Custom Security Header Check
```python
from keycloak_auditor.plugins.base import AuditPlugin

class SecurityHeaderPlugin(AuditPlugin):
    def get_name(self) -> str:
        return "security-headers"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_description(self) -> str:
        return "Check for custom security headers"
    
    def audit(self):
        findings = []
        try:
            response = self.http.request("GET", f"{self.config.base_url}/realms/{self.config.realm}/.well-known/openid-configuration")
            if response.ok:
                headers = {k.lower(): v for k, v in response.headers.items()}
                if "x-custom-security-header" not in headers:
                    findings.append({
                        "id": "missing_custom_header",
                        "title": "Missing custom security header",
                        "severity": "low",
                        "description": "The x-custom-security-header is not present",
                        "remediation": "Add x-custom-security-header to all responses"
                    })
        except Exception:
            pass
        return findings
```

### Custom Endpoint Discovery
```python
from keycloak_auditor.plugins.base import EnumerationPlugin

class EndpointDiscoveryPlugin(EnumerationPlugin):
    def get_name(self) -> str:
        return "endpoint-discovery"
    
    def get_version(self) -> str:
        return "1.0.0"
    
    def get_description(self) -> str:
        return "Discover custom endpoints"
    
    def enumerate(self):
        results = {}
        custom_endpoints = ["/custom/health", "/api/status", "/metrics"]
        available_endpoints = []
        
        for endpoint in custom_endpoints:
            try:
                response = self.http.request("GET", f"{self.config.base_url}{endpoint}")
                if response.status_code == 200:
                    available_endpoints.append({
                        "endpoint": endpoint,
                        "status": response.status_code,
                        "content_type": response.headers.get("content-type", "unknown")
                    })
            except Exception:
                pass
        
        results["custom_endpoints"] = available_endpoints
        return results
```

## Troubleshooting

### Plugin Not Loading
- Check that the plugin file is in the `plugins/` directory
- Ensure the plugin class inherits from the correct base class
- Verify the plugin file has no syntax errors

### Plugin Errors
- Check the console output for error messages
- Ensure your plugin handles exceptions properly
- Test your plugin logic independently

### Performance Issues
- Keep plugin execution time reasonable
- Use the provided HTTP client for rate limiting
- Avoid making too many requests in a single plugin
