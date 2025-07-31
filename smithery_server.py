#!/usr/bin/env python3
"""
Adaptador HTTP para el servidor MCP UniFi para Smithery
"""

import os
import sys
import asyncio
import logging
from typing import Dict, Any

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

def setup_environment():
    """
    Configura las variables de entorno para el servidor MCP
    """
    # Configurar valores por defecto si no están presentes
    defaults = {
        'UNIFI_ROUTER_IP': '192.168.1.1',
        'UNIFI_USERNAME': 'admin',
        'UNIFI_PASSWORD': 'password',
        'UNIFI_PORT': '443',
        'UNIFI_VERIFY_SSL': 'false',
        'UNIFI_API_TIMEOUT': '30'
    }
    
    for key, default_value in defaults.items():
        if not os.getenv(key):
            os.environ[key] = default_value
    
    logger.info(f"UniFi Router IP: {os.getenv('UNIFI_ROUTER_IP')}")
    logger.info(f"UniFi Port: {os.getenv('UNIFI_PORT')}")
    logger.info(f"SSL Verification: {os.getenv('UNIFI_VERIFY_SSL')}")


async def main():
    """
    Función principal para ejecutar el servidor MCP
    """
    try:
        # Configurar entorno
        setup_environment()
        
        # Configurar el puerto desde la variable de entorno PORT (requerido por Smithery)
        port = int(os.getenv('PORT', '3000'))
        host = os.getenv('HOST', '0.0.0.0')
        
        logger.info(f"Starting UniFi MCP Server for Smithery on {host}:{port}")
        
        # Importar y ejecutar el servidor MCP
        from unifi_mcp_server import mcp
        
        # Ejecutar el servidor MCP con transporte HTTP
        await mcp.run(transport="http", host=host, port=port)
        
    except ImportError as e:
        logger.error(f"Error importing MCP server: {e}")
        logger.error("Make sure unifi_mcp_server.py is in the same directory")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Error starting server: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    try:
        # Ejecutar el servidor
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)