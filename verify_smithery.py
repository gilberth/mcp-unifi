#!/usr/bin/env python3
"""
Script de verificación para el despliegue en Smithery

Verifica que todos los archivos necesarios estén presentes
y que la configuración sea válida para Smithery.
"""

import os
import sys
import yaml
import json
from pathlib import Path
from typing import List, Dict, Any


def check_file_exists(filepath: str) -> bool:
    """Verifica si un archivo existe"""
    return Path(filepath).exists()


def check_smithery_yaml() -> Dict[str, Any]:
    """Verifica la configuración de smithery.yaml"""
    result = {"valid": False, "errors": [], "warnings": []}
    
    if not check_file_exists("smithery.yaml"):
        result["errors"].append("smithery.yaml no encontrado")
        return result
    
    try:
        with open("smithery.yaml", "r") as f:
            config = yaml.safe_load(f)
        
        # Verificar campos requeridos
        required_fields = ["name", "description", "runtime", "http"]
        for field in required_fields:
            if field not in config:
                result["errors"].append(f"Campo requerido '{field}' faltante en smithery.yaml")
        
        # Verificar configuración HTTP
        if "http" in config:
            http_config = config["http"]
            if "start" not in http_config:
                result["errors"].append("Configuración 'http.start' faltante")
            
            if "properties" not in http_config:
                result["warnings"].append("No se encontraron propiedades HTTP configuradas")
            else:
                # Verificar propiedades requeridas
                properties = http_config["properties"]
                required_props = ["unifiRouterIp", "unifiUsername", "unifiPassword"]
                for prop in required_props:
                    if prop not in properties:
                        result["errors"].append(f"Propiedad requerida '{prop}' faltante")
        
        if not result["errors"]:
            result["valid"] = True
            
    except yaml.YAMLError as e:
        result["errors"].append(f"Error parsing YAML: {e}")
    except Exception as e:
        result["errors"].append(f"Error leyendo smithery.yaml: {e}")
    
    return result


def check_dockerfile() -> Dict[str, Any]:
    """Verifica el Dockerfile"""
    result = {"valid": False, "errors": [], "warnings": []}
    
    if not check_file_exists("Dockerfile"):
        result["errors"].append("Dockerfile no encontrado")
        return result
    
    try:
        with open("Dockerfile", "r") as f:
            content = f.read()
        
        # Verificar elementos esenciales
        required_elements = [
            "FROM python:",
            "COPY requirements.txt",
            "RUN pip install",
            "COPY .",
            "EXPOSE 3000",
            "CMD [\"python\", \"smithery_server.py\"]"
        ]
        
        for element in required_elements:
            if element not in content:
                result["errors"].append(f"Elemento requerido '{element}' faltante en Dockerfile")
        
        if not result["errors"]:
            result["valid"] = True
            
    except Exception as e:
        result["errors"].append(f"Error leyendo Dockerfile: {e}")
    
    return result


def check_python_files() -> Dict[str, Any]:
    """Verifica los archivos Python principales"""
    result = {"valid": False, "errors": [], "warnings": []}
    
    required_files = [
        "smithery_server.py",
        "unifi_mcp_server.py",
        "config.py",
        "requirements.txt"
    ]
    
    for file in required_files:
        if not check_file_exists(file):
            result["errors"].append(f"Archivo requerido '{file}' faltante")
    
    # Verificar requirements.txt
    if check_file_exists("requirements.txt"):
        try:
            with open("requirements.txt", "r") as f:
                requirements = f.read()
            
            required_packages = ["fastmcp", "httpx", "pydantic", "python-dotenv"]
            for package in required_packages:
                if package not in requirements:
                    result["warnings"].append(f"Paquete '{package}' no encontrado en requirements.txt")
                    
        except Exception as e:
            result["errors"].append(f"Error leyendo requirements.txt: {e}")
    
    # Verificar sintaxis de smithery_server.py
    if check_file_exists("smithery_server.py"):
        try:
            with open("smithery_server.py", "r") as f:
                content = f.read()
            
            # Verificar elementos clave
            if "setup_environment_from_smithery" not in content:
                result["errors"].append("Función setup_environment_from_smithery faltante")
            
            if "mcp.run(transport=\"http\", port=3000)" not in content:
                result["errors"].append("Configuración de transporte HTTP faltante")
                
        except Exception as e:
            result["errors"].append(f"Error verificando smithery_server.py: {e}")
    
    if not result["errors"]:
        result["valid"] = True
    
    return result


def check_documentation() -> Dict[str, Any]:
    """Verifica la documentación"""
    result = {"valid": False, "errors": [], "warnings": []}
    
    doc_files = [
        "README.md",
        "SMITHERY_DEPLOYMENT.md",
        ".env.example"
    ]
    
    for file in doc_files:
        if not check_file_exists(file):
            result["warnings"].append(f"Archivo de documentación '{file}' faltante")
    
    # Siempre válido para documentación (solo warnings)
    result["valid"] = True
    
    return result


def main():
    """Función principal de verificación"""
    print("\n🔍 Verificando configuración para Smithery...\n")
    
    checks = [
        ("Configuración Smithery", check_smithery_yaml),
        ("Dockerfile", check_dockerfile),
        ("Archivos Python", check_python_files),
        ("Documentación", check_documentation)
    ]
    
    all_valid = True
    total_errors = 0
    total_warnings = 0
    
    for check_name, check_func in checks:
        print(f"Verificando {check_name}...")
        result = check_func()
        
        if result["valid"]:
            print(f"  ✅ {check_name}: Válido")
        else:
            print(f"  ❌ {check_name}: Inválido")
            all_valid = False
        
        for error in result["errors"]:
            print(f"    ❌ Error: {error}")
            total_errors += 1
        
        for warning in result["warnings"]:
            print(f"    ⚠️  Warning: {warning}")
            total_warnings += 1
        
        print()
    
    # Resumen final
    print("\n" + "="*50)
    print("RESUMEN DE VERIFICACIÓN")
    print("="*50)
    
    if all_valid and total_errors == 0:
        print("✅ ¡LISTO PARA SMITHERY!")
        print("\nTodos los archivos están configurados correctamente.")
        print("Puedes proceder con el despliegue en Smithery.")
        
        if total_warnings > 0:
            print(f"\n⚠️  Se encontraron {total_warnings} advertencias (no críticas)")
        
        print("\nPróximos pasos:")
        print("1. Subir código a GitHub")
        print("2. Conectar repositorio en Smithery")
        print("3. Configurar variables de entorno")
        print("4. Desplegar")
        
        return 0
    else:
        print("❌ NO LISTO PARA SMITHERY")
        print(f"\nSe encontraron {total_errors} errores que deben corregirse.")
        
        if total_warnings > 0:
            print(f"También hay {total_warnings} advertencias.")
        
        print("\nPor favor, corrige los errores antes de desplegar.")
        return 1


if __name__ == "__main__":
    sys.exit(main())