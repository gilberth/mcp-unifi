#!/usr/bin/env python3
"""
Tests para el servidor MCP UniFi en Smithery

Ejecuta tests básicos para verificar que el servidor
funciona correctamente en el entorno de Smithery.
"""

import asyncio
import os
import sys
import json
from typing import Dict, Any
from unittest.mock import Mock, patch

# Configurar path para importar módulos
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def setup_test_environment():
    """Configura el entorno de prueba"""
    os.environ["UNIFI_ROUTER_IP"] = "192.168.1.1"
    os.environ["UNIFI_USERNAME"] = "test_user"
    os.environ["UNIFI_PASSWORD"] = "test_password"
    os.environ["UNIFI_PORT"] = "443"
    os.environ["UNIFI_VERIFY_SSL"] = "false"


def test_smithery_server_import():
    """Test que el servidor de Smithery se puede importar"""
    try:
        import smithery_server
        print("✅ smithery_server.py se importó correctamente")
        return True
    except Exception as e:
        print(f"❌ Error importando smithery_server.py: {e}")
        return False


def test_unifi_mcp_server_import():
    """Test que el servidor MCP principal se puede importar"""
    try:
        import unifi_mcp_server
        print("✅ unifi_mcp_server.py se importó correctamente")
        return True
    except Exception as e:
        print(f"❌ Error importando unifi_mcp_server.py: {e}")
        return False


def test_config_import():
    """Test que la configuración se puede importar"""
    try:
        import config
        print("✅ config.py se importó correctamente")
        return True
    except Exception as e:
        print(f"❌ Error importando config.py: {e}")
        return False


def test_environment_setup():
    """Test que la configuración de entorno funciona"""
    try:
        from smithery_server import setup_environment_from_smithery
        
        # Simular variables de Smithery
        os.environ["CONFIG_UNIFIROUTERIP"] = "192.168.1.100"
        os.environ["CONFIG_UNIFIUSERNAME"] = "smithery_user"
        os.environ["CONFIG_UNIFIPASSWORD"] = "smithery_pass"
        
        setup_environment_from_smithery()
        
        # Verificar que las variables se configuraron
        assert os.environ.get("UNIFI_ROUTER_IP") == "192.168.1.100"
        assert os.environ.get("UNIFI_USERNAME") == "smithery_user"
        assert os.environ.get("UNIFI_PASSWORD") == "smithery_pass"
        
        print("✅ Configuración de entorno desde Smithery funciona")
        return True
    except Exception as e:
        print(f"❌ Error en configuración de entorno: {e}")
        return False


def test_unifi_config():
    """Test que la configuración UniFi se crea correctamente"""
    try:
        from config import UniFiConfig
        
        config = UniFiConfig.from_env()
        
        assert config.router_ip == os.environ.get("UNIFI_ROUTER_IP")
        assert config.username == os.environ.get("UNIFI_USERNAME")
        assert config.password == os.environ.get("UNIFI_PASSWORD")
        
        print("✅ Configuración UniFi se crea correctamente")
        return True
    except Exception as e:
        print(f"❌ Error en configuración UniFi: {e}")
        return False


async def test_unifi_client_creation():
    """Test que el cliente UniFi se puede crear"""
    try:
        from unifi_mcp_server import UniFiClient
        
        client = UniFiClient()
        
        assert client.router_ip == os.environ.get("UNIFI_ROUTER_IP")
        assert client.username == os.environ.get("UNIFI_USERNAME")
        assert client.password == os.environ.get("UNIFI_PASSWORD")
        
        await client.close()
        
        print("✅ Cliente UniFi se crea correctamente")
        return True
    except Exception as e:
        print(f"❌ Error creando cliente UniFi: {e}")
        return False


def test_mcp_server_creation():
    """Test que el servidor MCP se puede crear"""
    try:
        from unifi_mcp_server import mcp
        
        # Verificar que el servidor MCP tiene herramientas
        tools = mcp.list_tools()
        
        expected_tools = [
            "list_devices",
            "list_clients",
            "get_system_info",
            "get_health_status",
            "analyze_network_performance"
        ]
        
        for tool in expected_tools:
            tool_found = any(t.name == tool for t in tools)
            if not tool_found:
                raise Exception(f"Herramienta '{tool}' no encontrada")
        
        print(f"✅ Servidor MCP creado con {len(tools)} herramientas")
        return True
    except Exception as e:
        print(f"❌ Error creando servidor MCP: {e}")
        return False


async def test_mock_api_calls():
    """Test con llamadas mock a la API"""
    try:
        from unifi_mcp_server import list_devices, list_clients
        
        # Mock de respuesta de la API
        mock_response = {
            "data": [
                {"name": "Test Device", "type": "uap", "state": 1},
                {"name": "Test Switch", "type": "usw", "state": 1}
            ]
        }
        
        with patch('unifi_mcp_server.unifi_client.get', return_value=mock_response):
            # Test list_devices
            devices_result = await list_devices()
            assert "data" in devices_result
            assert len(devices_result["data"]) == 2
            
            # Test list_clients
            clients_result = await list_clients()
            assert "data" in clients_result
        
        print("✅ Llamadas mock a la API funcionan")
        return True
    except Exception as e:
        print(f"❌ Error en llamadas mock: {e}")
        return False


async def run_async_tests():
    """Ejecuta tests asíncronos"""
    tests = [
        test_unifi_client_creation,
        test_mock_api_calls
    ]
    
    results = []
    for test in tests:
        try:
            result = await test()
            results.append(result)
        except Exception as e:
            print(f"❌ Error en test asíncrono: {e}")
            results.append(False)
    
    return results


def main():
    """Función principal de tests"""
    print("\n🧪 Ejecutando tests para Smithery...\n")
    
    # Configurar entorno de prueba
    setup_test_environment()
    
    # Tests síncronos
    sync_tests = [
        ("Importar smithery_server", test_smithery_server_import),
        ("Importar unifi_mcp_server", test_unifi_mcp_server_import),
        ("Importar config", test_config_import),
        ("Configuración de entorno", test_environment_setup),
        ("Configuración UniFi", test_unifi_config),
        ("Creación servidor MCP", test_mcp_server_creation)
    ]
    
    sync_results = []
    for test_name, test_func in sync_tests:
        print(f"Ejecutando: {test_name}")
        try:
            result = test_func()
            sync_results.append(result)
        except Exception as e:
            print(f"❌ Error en {test_name}: {e}")
            sync_results.append(False)
        print()
    
    # Tests asíncronos
    print("Ejecutando tests asíncronos...")
    try:
        async_results = asyncio.run(run_async_tests())
    except Exception as e:
        print(f"❌ Error ejecutando tests asíncronos: {e}")
        async_results = [False, False]
    
    # Resultados
    all_results = sync_results + async_results
    passed = sum(all_results)
    total = len(all_results)
    
    print("\n" + "="*50)
    print("RESULTADOS DE TESTS")
    print("="*50)
    
    print(f"Tests ejecutados: {total}")
    print(f"Tests pasados: {passed}")
    print(f"Tests fallidos: {total - passed}")
    
    if passed == total:
        print("\n✅ ¡TODOS LOS TESTS PASARON!")
        print("El servidor está listo para Smithery.")
        return 0
    else:
        print(f"\n❌ {total - passed} tests fallaron")
        print("Revisa los errores antes de desplegar.")
        return 1


if __name__ == "__main__":
    sys.exit(main())