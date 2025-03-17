# Using Proxies with the SecOps SDK

The SecOps SDK supports HTTP/HTTPS proxies through standard environment variables and Python's requests library configuration. This guide explains how to configure proxy settings when using the SDK.

## Table of Contents
- [Basic Proxy Configuration](#basic-proxy-configuration)
- [Authentication Methods](#authentication-methods)
- [Environment Variables](#environment-variables)
- [Programmatic Configuration](#programmatic-configuration)
- [SSL/TLS Certificates](#ssltls-certificates)
- [Troubleshooting](#troubleshooting)

## Basic Proxy Configuration

### Environment Variables Method (Recommended)

The simplest way to configure a proxy is through environment variables:

```bash
# For HTTP traffic
export HTTP_PROXY="http://proxy.example.com:3128"

# For HTTPS traffic (most common for Chronicle API)
export HTTPS_PROXY="http://proxy.example.com:3128"

# Optional: Bypass proxy for specific hosts
export NO_PROXY="localhost,127.0.0.1,.internal.domain"
```

Then use the SDK normally:
```python
from secops import SecOpsClient

# The client will automatically use the configured proxy
client = SecOpsClient()
chronicle = client.chronicle(region="us")
```

### Programmatic Configuration

You can also set proxy configuration in your code:

```python
import os

# Set proxy before initializing the SDK
os.environ['HTTPS_PROXY'] = 'http://proxy.example.com:3128'
os.environ['HTTP_PROXY'] = 'http://proxy.example.com:3128'

from secops import SecOpsClient
client = SecOpsClient()
```

## Authentication

### Proxy Authentication

If your proxy requires authentication:

```python
import os

# Format: protocol://username:password@host:port
os.environ['HTTPS_PROXY'] = 'http://user:pass@proxy.example.com:3128'

from secops import SecOpsClient
client = SecOpsClient()
```

### Google Authentication Through Proxy

The proxy configuration works transparently with all SDK authentication methods:

```python
import os

# Set proxy
os.environ['HTTPS_PROXY'] = 'http://proxy.example.com:3128'

# 1. Application Default Credentials (ADC)
client = SecOpsClient()  # Uses ADC through proxy

# 2. Service Account
client = SecOpsClient(service_account_path="/path/to/service-account.json")  # Uses proxy

# 3. Explicit credentials
client = SecOpsClient(credentials=your_credentials)  # Uses proxy
```

## SSL/TLS Configuration

### Custom Certificates

If your proxy uses custom SSL certificates:

```python
import os

# Option 1: Specify CA certificate
os.environ['REQUESTS_CA_BUNDLE'] = '/path/to/your/cert.pem'

# Option 2: Specify CA certificate directory
os.environ['REQUESTS_CA_PATH'] = '/path/to/your/certs/dir'
```

### Self-signed Certificates (Not Recommended for Production)

```python
import os
import urllib3

# Disable SSL verification warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set verify=False in your requests (NOT recommended for production)
os.environ['PYTHONWARNINGS'] = 'ignore:Unverified HTTPS request'
```

## Required Proxy Access

Your proxy must allow access to these Google domains:

- `*.googleapis.com` - API endpoints
- `accounts.google.com` - Authentication
- `oauth2.googleapis.com` - Token management

## Troubleshooting

### Common Issues

1. **Connection Errors**
   - Verify proxy URL and port are correct
   - Check if proxy requires authentication
   - Ensure proxy is accessible from your network
   - Verify required domains are allowlisted in proxy configuration

2. **SSL Certificate Errors**
   - Verify CA certificate path is correct
   - Ensure certificates are up to date
   - Check if proxy requires specific SSL configuration

3. **Authentication Issues**
   - Verify proxy credentials are correct
   - Check if proxy requires specific authentication headers
   - Ensure Google authentication endpoints are accessible

### Debug Logging

Enable debug logging to troubleshoot proxy issues:

```python
import logging

# Enable debug logging for requests and urllib3
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("urllib3").setLevel(logging.DEBUG)
```

### Environment Variables Reference

| Variable | Description |
|----------|-------------|
| `HTTP_PROXY` | Proxy for HTTP traffic |
| `HTTPS_PROXY` | Proxy for HTTPS traffic |
| `NO_PROXY` | Comma-separated list of hosts to exclude from proxying |
| `REQUESTS_CA_BUNDLE` | Path to CA certificate bundle |
| `REQUESTS_CA_PATH` | Path to directory containing CA certificates |

## Best Practices

1. Always set up proxies before initializing the SDK
2. Use environment variables for proxy configuration when possible
3. Ensure proper SSL certificate handling in production
4. Keep proxy access lists updated with required Google domains
5. Use secure HTTPS proxies in production environments
6. Implement proper error handling for proxy-related issues

## Example Implementation

Here's a complete example showing proper proxy configuration:

```python
import os
import logging
from secops import SecOpsClient
from secops.exceptions import SecOpsError

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configure proxy
os.environ['HTTPS_PROXY'] = 'http://proxy.example.com:3128'
os.environ['REQUESTS_CA_BUNDLE'] = '/path/to/cert.pem'

try:
    # Initialize client
    client = SecOpsClient()
    
    # Initialize Chronicle
    chronicle = client.chronicle(region="us")
    
    # Test connection
    response = chronicle.list_rules()
    logger.info("Successfully connected through proxy")
    
except SecOpsError as e:
    logger.error(f"Failed to connect: {e}")
```

