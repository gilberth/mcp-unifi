#!/usr/bin/env python3
"""
Servidor MCP UniFi Simplificado para Smithery
"""

import os
import sys
import asyncio
import logging
from urllib.parse import parse_qs, urlparse

# Configurar logging mínimo
logging.basicConfig(level=logging.INFO, stream=sys.stdout)
logger = logging.getLogger(__name__)

def setup_environment_from_query():
    """Configurar variables de entorno desde parámetros de consulta de Smithery"""
    
    # Obtener parámetros de la URL de consulta (enviados por Smithery)
    query_string = os.getenv('QUERY_STRING', '')
    if query_string:
        params = parse_qs(query_string)
        
        # Mapear parámetros de Smithery a variables de entorno
        param_mapping = {
            'unifiRouterIp': 'UNIFI_ROUTER_IP',
            'unifiUsername': 'UNIFI_USERNAME', 
            'unifiPassword': 'UNIFI_PASSWORD',
            'unifiPort': 'UNIFI_PORT',
            'unifiVerifySsl': 'UNIFI_VERIFY_SSL'
        }
        
        for smithery_param, env_var in param_mapping.items():
            if smithery_param in params and params[smithery_param]:
                value = params[smithery_param][0]
                os.environ[env_var] = str(value)
                logger.info(f"Set {env_var} from Smithery config")
    
    # Configurar valores por defecto si no están presentes
    defaults = {
        'UNIFI_ROUTER_IP': '192.168.1.1',
        'UNIFI_USERNAME': 'admin',
        'UNIFI_PASSWORD': 'password',
        'UNIFI_PORT': '443',
        'UNIFI_VERIFY_SSL': 'false'
    }
    
    for key, value in defaults.items():
        if not os.getenv(key):
            os.environ[key] = value
    
    logger.info(f"UniFi Router: {os.getenv('UNIFI_ROUTER_IP')}:{os.getenv('UNIFI_PORT')}")
    logger.info(f"SSL Verification: {os.getenv('UNIFI_VERIFY_SSL')}")

async def main():
    """Función principal"""
    try:
        setup_environment_from_query()
        
        port = int(os.getenv('PORT', '3000'))
        host = os.getenv('HOST', '0.0.0.0')
        
        logger.info(f"Starting UniFi MCP Server on {host}:{port}")
        
        # Importar servidor simplificado
        from simple_mcp_server import mcp
        
        # Ejecutar servidor
        await mcp.run(transport="http", host=host, port=port)
        
    except Exception as e:
        logger.error(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())