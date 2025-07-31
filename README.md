# UniFi MCP Server para Smithery

Un servidor MCP (Model Context Protocol) que permite a Claude interactuar con controladores UniFi locales a través de Smithery.

## 🚀 Despliegue Rápido en Smithery

### 1. Configuración Requerida

Antes de desplegar, necesitarás:

- **IP del Controlador UniFi**: La dirección IP de tu router/controlador UniFi
- **Usuario**: Usuario administrador de UniFi
- **Contraseña**: Contraseña del usuario administrador
- **Puerto** (opcional): Puerto del controlador (por defecto 443)
- **Verificación SSL** (opcional): true/false (por defecto true)

### 2. Desplegar en Smithery

1. Ve a [Smithery](https://smithery.ai)
2. Conecta este repositorio
3. Configura las variables de entorno:
   - `UNIFI_ROUTER_IP`: IP de tu controlador UniFi
   - `UNIFI_USERNAME`: Usuario administrador
   - `UNIFI_PASSWORD`: Contraseña
   - `UNIFI_PORT`: Puerto (opcional, por defecto 443)
   - `UNIFI_VERIFY_SSL`: Verificación SSL (opcional, por defecto true)

### 3. Configurar en Claude Desktop

Agrega esta configuración a tu `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "unifi": {
      "command": "npx",
      "args": ["-y", "@smithery/cli", "run", "TU_DEPLOYMENT_URL"],
      "env": {}
    }
  }
}
```

## 🛠️ Herramientas Disponibles

### Monitoreo de Red
- `list_devices` - Lista todos los dispositivos UniFi
- `list_clients` - Lista clientes conectados
- `get_system_info` - Información del sistema
- `get_health_status` - Estado de salud del sitio
- `get_device_health_summary` - Resumen de salud de dispositivos

### Gestión de Firewall
- `list_firewall_rules` - Lista reglas de firewall
- `get_firewall_rule` - Obtiene regla específica
- `list_firewall_groups` - Lista grupos de firewall
- `create_firewall_rule` - Crea nueva regla

### Configuración de Red
- `list_wlan_configs` - Configuraciones WLAN
- `list_network_configs` - Configuraciones de red
- `list_port_forwarding` - Reglas de port forwarding

### Análisis y Diagnóstico
- `analyze_network_performance` - Análisis de rendimiento
- `get_isp_metrics` - Métricas del ISP
- `query_isp_metrics` - Consulta métricas específicas

### Eventos y Alertas
- `list_events` - Eventos del sistema
- `list_alarms` - Alarmas activas

## 🔒 Seguridad

- Las credenciales se transmiten de forma segura
- Soporte para SSL/TLS configurable
- Acceso solo a la red local del controlador
- No se almacenan credenciales permanentemente

## 🧪 Prueba Local

Para probar localmente antes del despliegue:

```bash
# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus credenciales

# Ejecutar prueba
python test_smithery.py
```

## 📋 Requisitos

- Controlador UniFi accesible en la red
- Credenciales de administrador
- Python 3.8+ (para desarrollo local)

## 🆘 Solución de Problemas

### Error de Conexión
- Verifica que la IP del controlador sea correcta
- Asegúrate de que el puerto esté abierto
- Comprueba las credenciales

### Problemas SSL
- Si usas certificados autofirmados, configura `UNIFI_VERIFY_SSL=false`
- Verifica que el puerto SSL sea el correcto (443 por defecto)

### Logs y Debugging
- Los logs están disponibles en la consola de Smithery
- Para debugging local, usa `python test_smithery.py`

## 📚 Documentación Adicional

- [Documentación de Smithery](https://docs.smithery.ai)
- [Especificación MCP](https://modelcontextprotocol.io)
- [API de UniFi](https://ubntwiki.com/products/software/unifi-controller/api)

## 🤝 Contribuir

1. Fork el repositorio
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push a la rama
5. Abre un Pull Request

## 📄 Licencia

MIT License - ver archivo LICENSE para detalles.