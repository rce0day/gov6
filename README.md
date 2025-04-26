# Gov6 - Advanced IPv6 Rotating Proxy

[![Experimental](https://img.shields.io/badge/Status-Experimental-orange.svg)](https://github.com/rce0day/gov6)

## Note

Require a custom solution? feel free to reach out to me on telegram **@opensrc**.

## Overview

Gov6 is an experimental IPv6 proxy server that provides rotating IPv6 addresses for each connection. It's designed for applications requiring unique IP addresses for web scraping, testing, or anonymity purposes.

## ⚠️ Experimental Status

**IMPORTANT**: This project is currently experimental and may have stability issues. Use in production environments at your own risk. Features and API may change without notice.

## Key Features

- **Dynamic IPv6 Rotation**: Generates a unique IPv6 address for each request from your assigned IPv6 range
- **HTTP/HTTPS Proxy Support**: Handles both HTTP and HTTPS connections
- **User Management**: Multiple user accounts with authentication
- **Thread Limiting**: Control concurrent connection limits per user
- **Account Expiration**: Set expiration dates for user accounts
- **Admin API**: Manage users through a simple REST API

## Requirements

- Linux server with an IPv6 prefix allocation (/48, /64, /29 etc)
- MariaDB/MySQL database
- Root access (for network interface configuration)
- Go 1.21+

## Installation

1. Build and run:
   ```
   sh build.sh
   sudo ./ipv6-proxy
   ```

## Configuration

Edit the `.env` file to configure:

```
# Network Configuration
IPV6_RANGE=2605:6400:49f2::/48  # Your IPv6 prefix
PORT=7777                        # Proxy listen port
INTERFACE=eth0                   # Network interface

# Database Configuration
DB_HOST=localhost
DB_PORT=3306
DB_USER=proxyuser
DB_PASSWORD=your_secure_password
DB_NAME=proxy
ADMIN_API_KEY=change_me_to_secure_api_key

# Application Configuration
DB_REFRESH_INTERVAL=5m          # How often to refresh user data 
DEFAULT_THREAD_LIMIT=100        # Default thread limit for new users, this only applies if no value is passed.
```

## Usage

### Proxy Configuration

Configure your client to use the proxy:
- Proxy address: `http://your-server-address:7777`
- Authentication: Basic auth with username and password

### Admin API

Manage users using the admin API:

```bash
# Add a user
curl -X POST http://localhost:7777/manage \
  -H "X-API-Key: your_api_key" \
  -d '{"action":"add","username":"newuser","password":"password123","thread_limit":50,"expires_at":"2023-12-31"}'

# List users
curl -X POST http://localhost:7777/manage \
  -H "X-API-Key: your_api_key" \
  -d '{"action":"list"}'

# Update a user
curl -X POST http://localhost:7777/manage \
  -H "X-API-Key: your_api_key" \
  -d '{"action":"update","username":"newuser","thread_limit":200}'

# Delete a user
curl -X POST http://localhost:7777/manage \
  -H "X-API-Key: your_api_key" \
  -d '{"action":"delete","username":"newuser"}'
```

## Limitations

- IPv4-only sites are not supported (IPv6 required)
- Some websites may block traffic from IPv6 ranges
- Root access required for IPv6 address configuration
- Performance may vary based on your network configuration

## Security Considerations

- Change default credentials in the database
- Use a secure API key for the admin interface
- Consider implementing IP whitelisting for the admin API
- Keep the software updated for security patches


## Disclaimer

This software is provided for educational and research purposes only. Users are responsible for ensuring their usage complies with applicable laws and regulations.
