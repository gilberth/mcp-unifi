#!/usr/bin/env python3
"""
UniFi Local Controller MCP Server

Un servidor MCP completo para integrar con la API local del controlador UniFi.
Proporciona herramientas, recursos y prompts para gestionar redes UniFi localmente.
"""

import asyncio
import json
import os
import time
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urljoin

import httpx
import structlog
from dotenv import load_dotenv
from fastmcp import FastMCP
from pydantic import BaseModel, Field
from tenacity import retry, stop_after_attempt, wait_exponential

from config import UniFiConfig

# Cargar variables de entorno
load_dotenv()

# Configurar logging estructurado - redirigir a stderr para evitar interferir con STDIO
import sys
import logging

# Configurar logging para que vaya a stderr, no stdout
logging.basicConfig(
    level=logging.ERROR,  # Solo errores críticos
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr  # Importante: usar stderr en lugar de stdout
)

logger = structlog.get_logger()
# Configurar structlog para usar stderr
structlog.configure(
    wrapper_class=structlog.make_filtering_bound_logger(logging.WARNING),
    logger_factory=structlog.WriteLoggerFactory(file=sys.stderr),
    cache_logger_on_first_use=True,
)

# Configuración global
config = UniFiConfig.from_env()

# Configuración
UNIFI_ROUTER_IP = os.getenv("UNIFI_ROUTER_IP")
UNIFI_USERNAME = os.getenv("UNIFI_USERNAME")
UNIFI_PASSWORD = os.getenv("UNIFI_PASSWORD")
UNIFI_PORT = int(os.getenv("UNIFI_PORT", "443"))
UNIFI_API_TIMEOUT = int(os.getenv("UNIFI_API_TIMEOUT", "30"))
UNIFI_VERIFY_SSL = os.getenv("UNIFI_VERIFY_SSL", "false").lower() == "true"

# URLs de la API Local
PROTOCOL = "https" if UNIFI_PORT == 443 else "http"
UNIFI_API_BASE = f"{PROTOCOL}://{UNIFI_ROUTER_IP}:{UNIFI_PORT}" if UNIFI_ROUTER_IP else None

# Rate limits locales (más generosos)
RATE_LIMIT = 1000  # requests per minute


class RateLimiter:
    """Manejador de rate limiting con ventana deslizante"""
    
    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests = []
    
    async def acquire(self):
        """Adquiere permiso para hacer una request"""
        now = time.time()
        
        # Limpiar requests antiguas
        self.requests = [req_time for req_time in self.requests 
                        if now - req_time < self.window_seconds]
        
        # Verificar si podemos hacer la request
        if len(self.requests) >= self.max_requests:
            sleep_time = self.window_seconds - (now - self.requests[0])
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
                return await self.acquire()
        
        self.requests.append(now)


class UniFiClient:
    """Cliente para la API local del controlador UniFi"""
    
    def __init__(self):
        if not UNIFI_ROUTER_IP:
            raise ValueError("UNIFI_ROUTER_IP es requerido")
        if not UNIFI_USERNAME:
            raise ValueError("UNIFI_USERNAME es requerido")
        if not UNIFI_PASSWORD:
            raise ValueError("UNIFI_PASSWORD es requerido")
        
        self.router_ip = UNIFI_ROUTER_IP
        self.username = UNIFI_USERNAME
        self.password = UNIFI_PASSWORD
        self.port = UNIFI_PORT
        self.timeout = UNIFI_API_TIMEOUT
        self.api_base = UNIFI_API_BASE
        
        # Rate limiter
        self.rate_limiter = RateLimiter(RATE_LIMIT, 60)
        
        # Configurar cliente HTTP
        self.client = httpx.AsyncClient(
            timeout=self.timeout,
            verify=UNIFI_VERIFY_SSL,
            # Permitir cookies para mantener sesión
            cookies={}
        )
        
        # Estado de autenticación
        self.authenticated = False
        self.csrf_token = None
    
    async def login(self) -> bool:
        """Autentica con el controlador UniFi"""
        # Intentar primero con UniFi OS (UDM/UDR)
        unifi_os_login_url = f"{self.api_base}/api/auth/login"
        
        login_data = {
            "username": self.username,
            "password": self.password
        }
        
        try:
            # Intentar login con UniFi OS
            response = await self.client.post(
                unifi_os_login_url,
                json=login_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                # UniFi OS devuelve directamente los datos del usuario
                if data.get("unique_id") or data.get("_id"):
                    self.authenticated = True
                    # Extraer CSRF token si está disponible
                    self.csrf_token = response.headers.get("X-CSRF-Token")
                    return True
            
            # Si falla, intentar con controlador tradicional
            traditional_login_url = f"{self.api_base}/api/login"
            
            traditional_login_data = {
                "username": self.username,
                "password": self.password,
                "remember": False
            }
            
            response = await self.client.post(
                traditional_login_url,
                json=traditional_login_data,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("meta", {}).get("rc") == "ok":
                    self.authenticated = True
                    # Extraer CSRF token si está disponible
                    self.csrf_token = response.headers.get("X-CSRF-Token")
                    return True
            
            return False
            
        except Exception as e:
            return False
    
    async def logout(self):
        """Cierra sesión con el controlador"""
        if not self.authenticated:
            return
        
        try:
            logout_url = f"{self.api_base}/api/logout"
            await self.client.post(logout_url)
            self.authenticated = False
            self.csrf_token = None
        except Exception as e:
            pass
    
    async def ensure_authenticated(self):
        """Asegura que estemos autenticados"""
        if not self.authenticated:
            success = await self.login()
            if not success:
                raise Exception("No se pudo autenticar con el controlador UniFi")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def _make_request(
        self, 
        method: str, 
        url: str, 
        **kwargs
    ) -> Dict[str, Any]:
        """Hace una request HTTP con manejo de autenticación y retry"""
        
        # Asegurar autenticación
        await self.ensure_authenticated()
        
        # Aplicar rate limiting
        await self.rate_limiter.acquire()
        
        # Para UniFi OS, convertir endpoints de API tradicional a proxy
        if url.startswith("/api/s/"):
            # Convertir /api/s/sitename/... a /proxy/network/api/s/sitename/...
            url = url.replace("/api/", "/proxy/network/api/")
        elif url.startswith("/api/") and not url.startswith("/api/auth/"):
            # Convertir otros endpoints /api/... a /proxy/network/api/...
            url = url.replace("/api/", "/proxy/network/api/")
        
        full_url = urljoin(self.api_base, url)
        
        headers = {
            "Content-Type": "application/json",
            **kwargs.pop("headers", {})
        }
        
        # Agregar CSRF token si está disponible
        if self.csrf_token:
            headers["X-CSRF-Token"] = self.csrf_token
        
        try:
            response = await self.client.request(
                method=method,
                url=full_url,
                headers=headers,
                **kwargs
            )
            
            # Manejar errores de autenticación
            if response.status_code == 401:
                logger.warning("Token expirado, reautenticando...")
                self.authenticated = False
                await self.ensure_authenticated()
                # Reintentar con nueva autenticación
                raise httpx.HTTPStatusError(
                    "Authentication expired", 
                    request=response.request, 
                    response=response
                )
            
            response.raise_for_status()
            return response.json()
            
        except httpx.HTTPStatusError as e:
            raise
        except Exception as e:
            raise
    
    async def get(self, url: str, **kwargs) -> Dict[str, Any]:
        """Hace una request GET"""
        return await self._make_request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> Dict[str, Any]:
        """Hace una request POST"""
        return await self._make_request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> Dict[str, Any]:
        """Hace una request PUT"""
        return await self._make_request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> Dict[str, Any]:
        """Hace una request DELETE"""
        return await self._make_request("DELETE", url, **kwargs)
                
    async def close(self):
        """Cierra el cliente HTTP y hace logout"""
        await self.logout()
        await self.client.aclose()


# Inicializar cliente UniFi
unifi_client = UniFiClient()

# Inicializar servidor MCP
mcp = FastMCP("UniFi Local Controller")


# ============================================================================
# HERRAMIENTAS BÁSICAS
# ============================================================================

@mcp.tool()
async def list_devices(
    site_name: str = "default",
    device_type: Optional[str] = None,
    status: Optional[str] = None
) -> Dict[str, Any]:
    """
    Lista todos los dispositivos UniFi del sitio.
    
    Args:
        site_name: Nombre del sitio (default: "default")
        device_type: Tipo de dispositivo para filtrar (uap, usw, ugw, etc.)
        status: Estado para filtrar (online, offline, etc.)
    
    Returns:
        Lista de dispositivos con detalles
    """
    try:
        endpoint = f"/api/s/{site_name}/stat/device"
        response = await unifi_client.get(endpoint)
        
        devices = response.get("data", [])
        
        # Aplicar filtros
        if device_type:
            devices = [d for d in devices if d.get("type") == device_type]
        if status:
            if status == "online":
                devices = [d for d in devices if d.get("state") == 1]
            else:
                devices = [d for d in devices if d.get("state") != 1]
        
        # logger.info(f"Retrieved {len(devices)} devices from site {site_name}")
        return {"data": devices, "meta": {"count": len(devices)}}
    except Exception as e:
        logger.error(f"Error listing devices: {str(e)}")
        return {"error": str(e), "data": []}


@mcp.tool()
async def list_clients(
    site_name: str = "default",
    active_only: bool = True
) -> Dict[str, Any]:
    """
    Lista todos los clientes conectados al sitio.
    
    Args:
        site_name: Nombre del sitio (default: "default")
        active_only: Solo mostrar clientes activos
    
    Returns:
        Lista de clientes con detalles de conexión
    """
    try:
        endpoint = f"/api/s/{site_name}/stat/sta"
        response = await unifi_client.get(endpoint)
        
        clients = response.get("data", [])
        
        # Filtrar solo clientes activos si se solicita
        if active_only:
            clients = [c for c in clients if c.get("is_wired", False) or c.get("essid")]
        
        # logger.info(f"Retrieved {len(clients)} clients from site {site_name}")
        return {"data": clients, "meta": {"count": len(clients)}}
    except Exception as e:
        logger.error(f"Error listing clients: {str(e)}")
        return {"error": str(e), "data": []}


@mcp.tool()
async def get_system_info(site_name: str = "default") -> Dict[str, Any]:
    """
    Obtiene información del sistema del controlador.
    
    Args:
        site_name: Nombre del sitio (default: "default")
    
    Returns:
        Información del sistema y estadísticas
    """
    try:
        endpoint = f"/api/s/{site_name}/stat/sysinfo"
        response = await unifi_client.get(endpoint)
        
        # logger.info(f"Retrieved system info for site {site_name}")
        return response
    except Exception as e:
        logger.error(f"Error getting system info: {str(e)}")
        return {"error": str(e)}


@mcp.tool()
async def get_health_status(site_name: str = "default") -> Dict[str, Any]:
    """
    Obtiene el estado de salud del sitio.
    
    Args:
        site_name: Nombre del sitio (default: "default")
    
    Returns:
        Estado de salud de subsistemas
    """
    try:
        endpoint = f"/api/s/{site_name}/stat/health"
        response = await unifi_client.get(endpoint)
        
        # logger.info(f"Retrieved health status for site {site_name}")
        return response
    except Exception as e:
        logger.error(f"Error getting health status: {str(e)}")
        return {"error": str(e)}


@mcp.tool()
async def get_device_health_summary(site_name: str = "default") -> Dict[str, Any]:
    """
    Obtiene un resumen de salud de todos los dispositivos.
    
    Args:
        site_name: Nombre del sitio (default: "default")
    
    Returns:
        Resumen de salud con estadísticas agregadas
    """
    try:
        # Obtener todos los dispositivos directamente
        endpoint = f"/api/s/{site_name}/stat/device"
        devices_response = await unifi_client.get(endpoint)
        devices = devices_response.get("data", [])
        
        # Calcular estadísticas de salud
        total_devices = len(devices)
        online_devices = sum(1 for d in devices if d.get("state") == 1)
        offline_devices = total_devices - online_devices
        
        # Agrupar por tipo
        device_types = {}
        for device in devices:
            device_type = device.get("type", "unknown")
            if device_type not in device_types:
                device_types[device_type] = {"total": 0, "online": 0, "offline": 0}
            
            device_types[device_type]["total"] += 1
            if device.get("state") == 1:
                device_types[device_type]["online"] += 1
            else:
                device_types[device_type]["offline"] += 1
        
        summary = {
            "timestamp": datetime.utcnow().isoformat(),
            "site_name": site_name,
            "total_devices": total_devices,
            "online_devices": online_devices,
            "offline_devices": offline_devices,
            "health_percentage": round((online_devices / total_devices * 100) if total_devices > 0 else 0, 2),
            "device_types": device_types
        }
        
        # logger.info(f"Generated health summary for {total_devices} devices")
        return summary
        
    except Exception as e:
        logger.error(f"Error generating device health summary: {str(e)}")
        return {"error": str(e)}


# ============================================================================
# HERRAMIENTAS DE MÉTRICAS
# ============================================================================

@mcp.tool()
async def get_isp_metrics(
    site_name: str = "default",
    interval_hours: int = 1
) -> Dict[str, Any]:
    """
    Obtiene métricas básicas del sitio para análisis de conectividad.
    
    Args:
        site_name: Nombre del sitio (default: "default")
        interval_hours: Horas hacia atrás para obtener datos
    
    Returns:
        Métricas básicas del sitio
    """
    try:
        # Obtener información del sistema y salud
        health_response = await unifi_client.get(f"/api/s/{site_name}/stat/health")
        sysinfo_response = await unifi_client.get(f"/api/s/{site_name}/stat/sysinfo")
        
        # Obtener dispositivos para calcular métricas
        devices_response = await unifi_client.get(f"/api/s/{site_name}/stat/device")
        devices = devices_response.get("data", [])
        
        # Calcular métricas básicas
        total_devices = len(devices)
        online_devices = sum(1 for d in devices if d.get("state") == 1)
        
        metrics = {
            "timestamp": datetime.utcnow().isoformat(),
            "site_name": site_name,
            "interval_hours": interval_hours,
            "connectivity": {
                "total_devices": total_devices,
                "online_devices": online_devices,
                "offline_devices": total_devices - online_devices,
                "connectivity_percentage": round((online_devices / total_devices * 100) if total_devices > 0 else 0, 2)
            },
            "health_data": health_response.get("data", []),
            "system_info": sysinfo_response.get("data", [])
        }
        
        # logger.info(f"Retrieved basic metrics for site {site_name}")
        return metrics
    except Exception as e:
        logger.error(f"Error getting site metrics: {str(e)}")
        return {"error": str(e)}


@mcp.tool()
async def analyze_network_performance(site_name: str = "default") -> Dict[str, Any]:
    """
    Realiza un análisis completo del rendimiento de la red usando datos locales.
    
    Args:
        site_name: Nombre del sitio (default: "default")
    
    Returns:
        Análisis detallado con recomendaciones
    """
    try:
        # Obtener datos básicos del sitio
        devices_response = await unifi_client.get(f"/api/s/{site_name}/stat/device")
        clients_response = await unifi_client.get(f"/api/s/{site_name}/stat/sta")
        health_response = await unifi_client.get(f"/api/s/{site_name}/stat/health")
        
        devices = devices_response.get("data", [])
        clients = clients_response.get("data", [])
        health_data = health_response.get("data", [])
        
        # Calcular estadísticas de rendimiento
        total_devices = len(devices)
        online_devices = sum(1 for d in devices if d.get("state") == 1)
        total_clients = len(clients)
        active_clients = sum(1 for c in clients if c.get("is_wired", False) or c.get("essid"))
        
        analysis = {
            "timestamp": datetime.utcnow().isoformat(),
            "site_name": site_name,
            "network_health": {
                "total_devices": total_devices,
                "online_devices": online_devices,
                "offline_devices": total_devices - online_devices,
                "device_health_score": round((online_devices / total_devices * 100) if total_devices > 0 else 0, 2)
            },
            "client_statistics": {
                "total_clients": total_clients,
                "active_clients": active_clients,
                "client_activity_rate": round((active_clients / total_clients * 100) if total_clients > 0 else 0, 2)
            },
            "health_subsystems": health_data,
            "recommendations": []
        }
        
        # Generar recomendaciones basadas en métricas
        device_health = analysis["network_health"]["device_health_score"]
        
        if device_health < 90:
            analysis["recommendations"].append({
                "type": "device_health",
                "priority": "high",
                "message": f"Salud de dispositivos baja: {device_health}%"
            })
        elif device_health < 95:
            analysis["recommendations"].append({
                "type": "device_health",
                "priority": "medium",
                "message": f"Algunos dispositivos offline: {device_health}%"
            })
        else:
            analysis["recommendations"].append({
                "type": "device_health",
                "priority": "info",
                "message": f"Excelente salud de red: {device_health}%"
            })
        
        # Analizar subsistemas de salud
        for subsystem in health_data:
            if subsystem.get("status") != "ok":
                analysis["recommendations"].append({
                    "type": "subsystem_health",
                    "priority": "high",
                    "message": f"Subsistema {subsystem.get('subsystem', 'unknown')} tiene problemas"
                })
        
        # logger.info("Generated network performance analysis")
        return analysis
        
    except Exception as e:
        logger.error(f"Error analyzing network performance: {str(e)}")
        return {"error": str(e)}


@mcp.tool()
async def query_isp_metrics(
    site_name: str = "default",
    metric_type: str = "device_stats",
    time_range: str = "1h"
) -> Dict[str, Any]:
    """
    Consulta métricas específicas del sitio UniFi local.
    
    Args:
        site_name: Nombre del sitio (default: "default")
        metric_type: Tipo de métrica (device_stats, client_stats, health_stats)
        time_range: Rango de tiempo (no aplicable para API local)
    
    Returns:
        Métricas específicas del sitio
    """
    try:
        result = {
            "timestamp": datetime.utcnow().isoformat(),
            "site_name": site_name,
            "metric_type": metric_type,
            "time_range": time_range,
            "data": {}
        }
        
        if metric_type == "device_stats":
            # Obtener estadísticas de dispositivos
            devices_response = await unifi_client.get(f"/api/s/{site_name}/stat/device")
            devices = devices_response.get("data", [])
            
            result["data"] = {
                "total_devices": len(devices),
                "device_types": {},
                "device_states": {"online": 0, "offline": 0},
                "devices": []
            }
            
            for device in devices:
                device_type = device.get("type", "unknown")
                device_state = "online" if device.get("state") == 1 else "offline"
                
                result["data"]["device_types"][device_type] = result["data"]["device_types"].get(device_type, 0) + 1
                result["data"]["device_states"][device_state] += 1
                
                result["data"]["devices"].append({
                    "name": device.get("name", "Unknown"),
                    "type": device_type,
                    "state": device_state,
                    "model": device.get("model", "Unknown"),
                    "version": device.get("version", "Unknown")
                })
        
        elif metric_type == "client_stats":
            # Obtener estadísticas de clientes
            clients_response = await unifi_client.get(f"/api/s/{site_name}/stat/sta")
            clients = clients_response.get("data", [])
            
            result["data"] = {
                "total_clients": len(clients),
                "connection_types": {"wired": 0, "wireless": 0},
                "clients": []
            }
            
            for client in clients:
                is_wired = client.get("is_wired", False)
                connection_type = "wired" if is_wired else "wireless"
                result["data"]["connection_types"][connection_type] += 1
                
                result["data"]["clients"].append({
                    "hostname": client.get("hostname", "Unknown"),
                    "connection_type": connection_type,
                    "essid": client.get("essid", "N/A"),
                    "ip": client.get("ip", "Unknown"),
                    "mac": client.get("mac", "Unknown")
                })
        
        elif metric_type == "health_stats":
            # Obtener estadísticas de salud
            health_response = await unifi_client.get(f"/api/s/{site_name}/stat/health")
            health_data = health_response.get("data", [])
            
            result["data"] = {
                "subsystems": [],
                "overall_status": "ok"
            }
            
            for subsystem in health_data:
                status = subsystem.get("status", "unknown")
                if status != "ok":
                    result["data"]["overall_status"] = "warning"
                
                result["data"]["subsystems"].append({
                    "subsystem": subsystem.get("subsystem", "unknown"),
                    "status": status,
                    "num_user": subsystem.get("num_user", 0),
                    "num_guest": subsystem.get("num_guest", 0),
                    "num_iot": subsystem.get("num_iot", 0)
                })
        
        else:
            result["data"] = {"error": f"Tipo de métrica no soportado: {metric_type}"}
        
        # logger.info(f"Queried {metric_type} metrics for site {site_name}")
        return result
        
    except Exception as e:
        logger.error(f"Error querying metrics: {str(e)}")
        return {"error": str(e)}


# ============================================================================
# HERRAMIENTAS DE FIREWALL (API LOCAL)
# ============================================================================

@mcp.tool()
async def list_firewall_rules(site_id: str = "default") -> Dict[str, Any]:
    """
    Lista todas las reglas de firewall del sitio.
    
    Args:
        site_id: ID del sitio (default: "default")
    
    Returns:
        Lista de reglas de firewall
    """
    try:
        endpoint = config.get_firewall_rules_endpoint(site_id)
        response = await unifi_client.get(endpoint)
        
        # Procesar y organizar las reglas
        rules = response.get("data", [])
        organized_rules = {
            "total_rules": len(rules),
            "enabled_rules": len([r for r in rules if r.get("enabled", True)]),
            "rules_by_action": {},
            "rules": rules
        }
        
        # Agrupar por acción
        for rule in rules:
            action = rule.get("action", "unknown")
            if action not in organized_rules["rules_by_action"]:
                organized_rules["rules_by_action"][action] = 0
            organized_rules["rules_by_action"][action] += 1
        
        # logger.info(f"Retrieved {len(rules)} firewall rules for site {site_id}")
        return organized_rules
        
    except Exception as e:
        logger.error(f"Error listing firewall rules: {str(e)}")
        return {"error": str(e), "rules": []}


@mcp.tool()
async def get_firewall_rule(rule_id: str, site_id: str = "default") -> Dict[str, Any]:
    """
    Obtiene una regla de firewall específica.
    
    Args:
        rule_id: ID de la regla de firewall
        site_id: ID del sitio (default: "default")
    
    Returns:
        Detalles de la regla de firewall
    """
    try:
        endpoint = config.get_firewall_rules_endpoint(site_id)
        response = await unifi_client.get(endpoint)
        
        rules = response.get("data", [])
        rule = next((r for r in rules if r.get("_id") == rule_id), None)
        
        if not rule:
            return {"error": f"Firewall rule {rule_id} not found"}
        
        # logger.info(f"Retrieved firewall rule {rule_id}")
        return rule
        
    except Exception as e:
        logger.error(f"Error getting firewall rule {rule_id}: {str(e)}")
        return {"error": str(e)}


@mcp.tool()
async def list_firewall_groups(site_id: str = "default") -> Dict[str, Any]:
    """
    Lista todos los grupos de firewall del sitio.
    
    Args:
        site_id: ID del sitio (default: "default")
    
    Returns:
        Lista de grupos de firewall
    """
    try:
        endpoint = config.get_firewall_groups_endpoint(site_id)
        response = await unifi_client.get(endpoint)
        
        groups = response.get("data", [])
        organized_groups = {
            "total_groups": len(groups),
            "groups_by_type": {},
            "groups": groups
        }
        
        # Agrupar por tipo
        for group in groups:
            group_type = group.get("group_type", "unknown")
            if group_type not in organized_groups["groups_by_type"]:
                organized_groups["groups_by_type"][group_type] = 0
            organized_groups["groups_by_type"][group_type] += 1
        
        # logger.info(f"Retrieved {len(groups)} firewall groups for site {site_id}")
        return organized_groups
        
    except Exception as e:
        logger.error(f"Error listing firewall groups: {str(e)}")
        return {"error": str(e), "groups": []}


@mcp.tool()
async def create_firewall_rule(
    name: str,
    action: str,
    protocol: str,
    src_address: str,
    dst_address: str,
    dst_port: Optional[str] = None,
    enabled: bool = True,
    site_id: str = "default"
) -> Dict[str, Any]:
    """
    Crea una nueva regla de firewall.
    
    Args:
        name: Nombre de la regla
        action: Acción (accept, drop, reject)
        protocol: Protocolo (tcp, udp, icmp, all)
        src_address: Dirección origen
        dst_address: Dirección destino
        dst_port: Puerto destino (opcional)
        enabled: Si la regla está habilitada
        site_id: ID del sitio
    
    Returns:
        Resultado de la creación
    """
    try:
        rule_data = {
            "name": name,
            "action": action,
            "protocol": protocol,
            "src_address": src_address,
            "dst_address": dst_address,
            "enabled": enabled
        }
        
        if dst_port:
            rule_data["dst_port"] = dst_port
        
        endpoint = config.get_firewall_rules_endpoint(site_id)
        response = await unifi_client.post(endpoint, json=rule_data)
        
        # logger.info(f"Created firewall rule: {name}")
        return response
        
    except Exception as e:
        logger.error(f"Error creating firewall rule: {str(e)}")
        return {"error": str(e)}


# ============================================================================
# HERRAMIENTAS DE CONFIGURACIÓN DE RED (API LOCAL)
# ============================================================================

@mcp.tool()
async def list_wlan_configs(site_id: str = "default") -> Dict[str, Any]:
    """
    Lista todas las configuraciones de WLAN.
    
    Args:
        site_id: ID del sitio (default: "default")
    
    Returns:
        Lista de configuraciones WLAN
    """
    try:
        endpoint = config.get_wlan_configs_endpoint(site_id)
        response = await unifi_client.get(endpoint)
        
        wlans = response.get("data", [])
        organized_wlans = {
            "total_wlans": len(wlans),
            "enabled_wlans": len([w for w in wlans if w.get("enabled", True)]),
            "wlans_by_security": {},
            "wlans": wlans
        }
        
        # Agrupar por tipo de seguridad
        for wlan in wlans:
            security = wlan.get("security", "unknown")
            if security not in organized_wlans["wlans_by_security"]:
                organized_wlans["wlans_by_security"][security] = 0
            organized_wlans["wlans_by_security"][security] += 1
        
        # logger.info(f"Retrieved {len(wlans)} WLAN configs for site {site_id}")
        return organized_wlans
        
    except Exception as e:
        logger.error(f"Error listing WLAN configs: {str(e)}")
        return {"error": str(e), "wlans": []}


@mcp.tool()
async def list_network_configs(site_id: str = "default") -> Dict[str, Any]:
    """
    Lista todas las configuraciones de red (VLANs, etc.).
    
    Args:
        site_id: ID del sitio (default: "default")
    
    Returns:
        Lista de configuraciones de red
    """
    try:
        endpoint = config.get_network_configs_endpoint(site_id)
        response = await unifi_client.get(endpoint)
        
        networks = response.get("data", [])
        organized_networks = {
            "total_networks": len(networks),
            "networks_by_purpose": {},
            "networks": networks
        }
        
        # Agrupar por propósito
        for network in networks:
            purpose = network.get("purpose", "unknown")
            if purpose not in organized_networks["networks_by_purpose"]:
                organized_networks["networks_by_purpose"][purpose] = 0
            organized_networks["networks_by_purpose"][purpose] += 1
        
        # logger.info(f"Retrieved {len(networks)} network configs for site {site_id}")
        return organized_networks
        
    except Exception as e:
        logger.error(f"Error listing network configs: {str(e)}")
        return {"error": str(e), "networks": []}


# ============================================================================
# SERVIDOR PRINCIPAL
# ============================================================================

async def main():
    """Función principal del servidor MCP"""
    
    try:
        # Verificar configuración
        config = UniFiConfig.from_env()
        
        # Ejecutar servidor MCP usando run_async para evitar conflictos con loops existentes
        await mcp.run_async()
        
    except KeyboardInterrupt:
        pass
    except Exception as e:
        pass
    finally:
        # Limpiar recursos
        await unifi_client.close()


if __name__ == "__main__":
    try:
        # Intentar ejecutar en un nuevo loop
        asyncio.run(main())
    except RuntimeError as e:
        if "asyncio.run() cannot be called from a running event loop" in str(e):
            # Si ya hay un loop ejecutándose, crear una tarea
            loop = asyncio.get_event_loop()
            task = loop.create_task(main())
            # Esperar a que la tarea termine si es posible
            try:
                loop.run_until_complete(task)
            except RuntimeError:
                # Si no se puede esperar, al menos crear la tarea
                pass
        else:
            raise