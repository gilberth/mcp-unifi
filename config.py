#!/usr/bin/env python3
"""
Configuración para el servidor MCP UniFi
"""

import os
from typing import Optional
from pydantic import BaseModel, Field


class UniFiConfig(BaseModel):
    """Configuración para el cliente UniFi"""
    
    router_ip: str = Field(..., description="IP del router/controlador UniFi")
    username: str = Field(..., description="Usuario para autenticación")
    password: str = Field(..., description="Contraseña para autenticación")
    port: int = Field(default=443, description="Puerto del controlador")
    verify_ssl: bool = Field(default=False, description="Verificar certificados SSL")
    timeout: int = Field(default=30, description="Timeout para requests HTTP")
    
    @classmethod
    def from_env(cls) -> "UniFiConfig":
        """Crea configuración desde variables de entorno"""
        return cls(
            router_ip=os.getenv("UNIFI_ROUTER_IP", ""),
            username=os.getenv("UNIFI_USERNAME", ""),
            password=os.getenv("UNIFI_PASSWORD", ""),
            port=int(os.getenv("UNIFI_PORT", "443")),
            verify_ssl=os.getenv("UNIFI_VERIFY_SSL", "false").lower() == "true",
            timeout=int(os.getenv("UNIFI_API_TIMEOUT", "30"))
        )
    
    def get_api_base(self) -> str:
        """Obtiene la URL base de la API"""
        protocol = "https" if self.port == 443 else "http"
        return f"{protocol}://{self.router_ip}:{self.port}"
    
    def get_firewall_rules_endpoint(self, site_id: str = "default") -> str:
        """Obtiene el endpoint para reglas de firewall"""
        return f"/api/s/{site_id}/rest/firewallrule"
    
    def get_firewall_groups_endpoint(self, site_id: str = "default") -> str:
        """Obtiene el endpoint para grupos de firewall"""
        return f"/api/s/{site_id}/rest/firewallgroup"
    
    def get_wlan_configs_endpoint(self, site_id: str = "default") -> str:
        """Obtiene el endpoint para configuraciones WLAN"""
        return f"/api/s/{site_id}/rest/wlanconf"
    
    def get_network_configs_endpoint(self, site_id: str = "default") -> str:
        """Obtiene el endpoint para configuraciones de red"""
        return f"/api/s/{site_id}/rest/networkconf"
    
    def get_port_forwarding_endpoint(self, site_id: str = "default") -> str:
        """Obtiene el endpoint para port forwarding"""
        return f"/api/s/{site_id}/rest/portforward"
    
    def get_events_endpoint(self, site_id: str = "default") -> str:
        """Obtiene el endpoint para eventos"""
        return f"/api/s/{site_id}/stat/event"
    
    def get_alarms_endpoint(self, site_id: str = "default") -> str:
        """Obtiene el endpoint para alarmas"""
        return f"/api/s/{site_id}/stat/alarm"