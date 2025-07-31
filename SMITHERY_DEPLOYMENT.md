# Despliegue del Servidor MCP UniFi en Smithery

Esta guía te ayudará a desplegar el servidor MCP UniFi en Smithery para integrarlo con Claude Desktop.

## Requisitos Previos

- Cuenta en [Smithery](https://smithery.ai)
- Controlador UniFi local accesible
- Claude Desktop instalado

## Pasos para el Despliegue

### 1. Preparar el Repositorio

El proyecto ya está configurado para Smithery con:
- `smithery.yaml` - Configuración de Smithery
- `Dockerfile` - Imagen de contenedor
- `smithery_server.py` - Adaptador para Smithery

### 2. Conectar Repositorio en Smithery

1. Inicia sesión en [Smithery](https://smithery.ai)
2. Ve a "New Deployment" o "Crear Despliegue"
3. Conecta este repositorio de GitHub: `https://github.com/gilberth/mcp-unifi`
4. Smithery detectará automáticamente el archivo `smithery.yaml`

### 3. Configurar Variables de Entorno

En la configuración de Smithery, establece las siguientes variables:

#### Variables Requeridas:
- `unifiRouterIp`: IP de tu controlador UniFi (ej: `192.168.1.1`)
- `unifiUsername`: Usuario del controlador UniFi
- `unifiPassword`: Contraseña del controlador UniFi

#### Variables Opcionales:
- `unifiPort`: Puerto del controlador (default: `443`)
- `unifiVerifySsl`: Verificar SSL (default: `false`)

### 4. Desplegar

1. Haz clic en "Deploy" en Smithery
2. Espera a que el despliegue se complete
3. Anota la URL del servidor MCP que proporciona Smithery

### 5. Configurar Claude Desktop

Agrega la configuración a tu archivo `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "unifi": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-fetch", "TU_URL_DE_SMITHERY"]
    }
  }
}
```

Reemplaza `TU_URL_DE_SMITHERY` con la URL proporcionada por Smithery.

### 6. Reiniciar Claude Desktop

Reinicia Claude Desktop para que cargue la nueva configuración.

## Verificación

Puedes verificar que el servidor funciona correctamente preguntando a Claude:

- "Lista todos los dispositivos UniFi"
- "Muestra el estado de salud de la red"
- "Analiza el rendimiento de la red"

## Herramientas Disponibles

Una vez configurado, tendrás acceso a:

### Monitoreo de Red
- `list_devices` - Lista dispositivos UniFi
- `list_clients` - Lista clientes conectados
- `get_system_info` - Información del sistema
- `get_health_status` - Estado de salud
- `get_device_health_summary` - Resumen de salud

### Gestión de Firewall
- `list_firewall_rules` - Lista reglas de firewall
- `get_firewall_rule` - Obtiene regla específica
- `list_firewall_groups` - Lista grupos de firewall
- `create_firewall_rule` - Crea nueva regla

### Configuración de Red
- `list_wlan_configs` - Lista configuraciones WLAN
- `list_network_configs` - Lista configuraciones de red

### Análisis y Diagnóstico
- `get_isp_metrics` - Métricas básicas
- `analyze_network_performance` - Análisis de rendimiento
- `query_isp_metrics` - Consulta métricas específicas

## Consideraciones de Seguridad

- **Credenciales**: Las credenciales se almacenan de forma segura en Smithery
- **Acceso Local**: El servidor solo accede a tu controlador UniFi local
- **SSL**: Se recomienda usar HTTPS cuando sea posible
- **Firewall**: Asegúrate de que el controlador UniFi sea accesible desde Smithery

## Solución de Problemas

### Error de Conexión
- Verifica que la IP del controlador sea correcta
- Asegúrate de que el puerto esté abierto
- Verifica las credenciales

### Error de Autenticación
- Confirma el usuario y contraseña
- Verifica que el usuario tenga permisos de administrador

### Problemas de SSL
- Si usas certificados autofirmados, establece `unifiVerifySsl` a `false`

## Soporte

Para problemas o preguntas:
1. Revisa los logs en Smithery
2. Verifica la configuración de red
3. Consulta la documentación de UniFi

## Actualizaciones

Para actualizar el servidor:
1. Haz push de los cambios al repositorio
2. Smithery detectará automáticamente los cambios
3. Redesplegará automáticamente