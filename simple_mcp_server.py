#!/usr/bin/env python3
"""
Servidor MCP UniFi Simple usando FastMCP
"""

import os
import logging
from fastmcp import FastMCP

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Crear instancia del servidor MCP
mcp = FastMCP("UniFi Basic MCP Server")

# Obtener configuración de variables de entorno
UNIFI_IP = os.getenv('UNIFI_ROUTER_IP', '192.168.1.1')
UNIFI_PORT = os.getenv('UNIFI_PORT', '443')
UNIFI_USERNAME = os.getenv('UNIFI_USERNAME', 'admin')
UNIFI_PASSWORD = os.getenv('UNIFI_PASSWORD', 'password')
UNIFI_VERIFY_SSL = os.getenv('UNIFI_VERIFY_SSL', 'false').lower() == 'true'

@mcp.tool()
def get_unifi_status() -> str:
    """Get UniFi controller status and basic information"""
    return f"""UniFi Controller Status:
- IP: {UNIFI_IP}:{UNIFI_PORT}
- Username: {UNIFI_USERNAME}
- SSL Verify: {UNIFI_VERIFY_SSL}
- Status: Connected (simulated)
- Version: 7.5.176 (simulated)
- Uptime: 5 days, 3 hours (simulated)

Note: This is a basic simulation. Real implementation would connect to the actual UniFi controller."""

@mcp.tool()
def list_devices(device_type: str = "all") -> str:
    """
    List all UniFi network devices
    
    Args:
        device_type: Filter by device type (ap, switch, gateway, all)
    """
    devices_info = f"""UniFi Devices (filter: {device_type}):

1. Access Point - UAP-AC-PRO
   - Status: Online
   - IP: 192.168.1.10
   - Clients: 8 connected

2. Switch - US-24-250W  
   - Status: Online
   - IP: 192.168.1.11
   - Ports: 24 (12 active)

3. Gateway - UDM-Pro
   - Status: Online
   - IP: {UNIFI_IP}
   - WAN: Connected

Note: This is simulated data. Real implementation would connect to {UNIFI_IP}:{UNIFI_PORT}"""
    
    return devices_info

@mcp.tool()
def get_network_info(include_clients: bool = False) -> str:
    """
    Get network information and statistics
    
    Args:
        include_clients: Include connected clients information
    """
    clients_info = """
Connected Clients:
- Total: 15 devices
- WiFi: 10 devices  
- Wired: 5 devices
- Guest: 2 devices""" if include_clients else ""
    
    network_info = f"""Network Information:
- Controller: {UNIFI_IP}:{UNIFI_PORT}
- Networks: 3 configured
  * Main Network (192.168.1.0/24)
  * Guest Network (192.168.100.0/24)  
  * IoT Network (192.168.200.0/24)
- Total Bandwidth: 1 Gbps
- Internet Status: Connected{clients_info}

Note: This is simulated data from basic server."""
    
    return network_info

@mcp.tool()
def get_device_health() -> str:
    """Get health status of all UniFi devices"""
    return f"""Device Health Summary:
- Total Devices: 3
- Online: 3
- Offline: 0
- Health Score: 100%

Device Details:
1. UDM-Pro (Gateway): Excellent
   - CPU: 15%
   - Memory: 45%
   - Temperature: 42°C

2. UAP-AC-PRO (Access Point): Good
   - CPU: 8%
   - Memory: 32%
   - Temperature: 38°C

3. US-24-250W (Switch): Excellent
   - CPU: 5%
   - Memory: 28%
   - Temperature: 35°C

Controller: {UNIFI_IP}:{UNIFI_PORT}"""

if __name__ == "__main__":
    logger.info(f"Starting UniFi MCP Server")
    logger.info(f"UniFi Controller: {UNIFI_IP}:{UNIFI_PORT}")
    logger.info(f"SSL Verification: {UNIFI_VERIFY_SSL}")