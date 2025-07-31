#!/usr/bin/env python3
"""
Adaptador del servidor MCP UniFi para Smithery

Este archivo actúa como punto de entrada para Smithery,
configurando las variables de entorno desde la configuración
de Smithery y luego iniciando el servidor MCP principal.
"""

import os
import asyncio
from typing import Dict, Any

# Configurar variables de entorno desde Smithery
def setup_environment_from_smithery():
    """Configura las variables de entorno desde la configuración de Smithery"""
    
    # Mapeo de configuración de Smithery a variables de entorno
    smithery_to_env = {
        "unifiRouterIp": "UNIFI_ROUTER_IP",
        "unifiUsername": "UNIFI_USERNAME", 
        "unifiPassword": "UNIFI_PASSWORD",
        "unifiPort": "UNIFI_PORT",
        "unifiVerifySsl": "UNIFI_VERIFY_SSL"
    }
    
    # Configurar variables de entorno desde variables del sistema
    for smithery_key, env_key in smithery_to_env.items():
        # Smithery pasa la configuración como variables de entorno con prefijo
        smithery_env_key = f"CONFIG_{smithery_key.upper()}"
        if smithery_env_key in os.environ:
            os.environ[env_key] = os.environ[smithery_env_key]
        # También verificar sin prefijo por compatibilidad
        elif smithery_key in os.environ:
            os.environ[env_key] = os.environ[smithery_key]
    
    # Configurar valores por defecto si no están presentes
    if "UNIFI_PORT" not in os.environ:
        os.environ["UNIFI_PORT"] = "443"
    
    if "UNIFI_VERIFY_SSL" not in os.environ:
        os.environ["UNIFI_VERIFY_SSL"] = "false"
    
    # Configurar timeout por defecto
    if "UNIFI_API_TIMEOUT" not in os.environ:
        os.environ["UNIFI_API_TIMEOUT"] = "30"


async def main():
    """Función principal para Smithery"""
    try:
        # Configurar entorno desde Smithery
        setup_environment_from_smithery()
        
        # Importar y ejecutar el servidor MCP principal
        from unifi_mcp_server import mcp
        
        # Ejecutar servidor MCP con transporte HTTP
        await mcp.run(transport="http", port=3000)
        
    except Exception as e:
        print(f"Error starting MCP server: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    import sys
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped by user", file=sys.stderr)
    except Exception as e:
        print(f"Fatal error: {e}", file=sys.stderr)
        sys.exit(1)