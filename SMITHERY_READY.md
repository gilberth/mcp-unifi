# Servidor MCP UniFi - Listo para Smithery

✅ **Estado**: Completamente preparado para despliegue en Smithery

## Resumen

Este proyecto contiene un servidor MCP (Model Context Protocol) completo para gestionar redes UniFi a través de Claude Desktop. El servidor está optimizado para desplegarse en Smithery y proporciona una integración perfecta con la IA.

## Archivos Configurados para Smithery

### Configuración Principal
- ✅ `smithery.yaml` - Configuración de Smithery con propiedades HTTP
- ✅ `smithery_server.py` - Adaptador del servidor para Smithery
- ✅ `Dockerfile` - Imagen de contenedor optimizada
- ✅ `.dockerignore` - Exclusiones para Docker

### Servidor MCP
- ✅ `unifi_mcp_server.py` - Servidor MCP principal con todas las herramientas
- ✅ `config.py` - Configuración y endpoints de la API UniFi
- ✅ `requirements.txt` - Dependencias de Python

### Documentación
- ✅ `README.md` - Documentación completa del proyecto
- ✅ `SMITHERY_DEPLOYMENT.md` - Guía de despliegue en Smithery
- ✅ `.env.example` - Ejemplo de variables de entorno

### Scripts de Utilidad
- ✅ `verify_smithery.py` - Script de verificación
- ✅ `test_smithery.py` - Tests para Smithery

## Configuración Requerida en Smithery

Cuando despliegues en Smithery, configura estas variables de entorno:

### Variables Obligatorias
```
unifiRouterIp=192.168.1.1
unifiUsername=admin
unifiPassword=tu_password
```

### Variables Opcionales
```
unifiPort=443
unifiVerifySsl=false
```

## Próximos Pasos

1. **Subir a Git**: ✅ Completado - Repositorio en GitHub
2. **Desplegar en Smithery**:
   - Conectar repositorio: `https://github.com/gilberth/mcp-unifi`
   - Configurar variables de entorno
   - Desplegar
3. **Configurar Claude Desktop**:
   - Agregar servidor MCP con URL de Smithery
   - Reiniciar Claude Desktop

## Configuración para Claude Desktop

Una vez desplegado en Smithery, agrega esto a `claude_desktop_config.json`:

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

## Herramientas Disponibles

### 📊 Monitoreo
- Lista dispositivos UniFi
- Monitorea clientes conectados
- Estado de salud del sistema
- Resumen de salud de dispositivos

### 🔥 Firewall
- Lista y gestiona reglas de firewall
- Administra grupos de firewall
- Crea nuevas reglas de seguridad

### 🌐 Red
- Configuraciones WLAN
- Configuraciones de red y VLANs
- Port forwarding

### 📈 Análisis
- Métricas de rendimiento
- Análisis de conectividad
- Diagnósticos de red

### 🚨 Eventos y Alertas
- Eventos del sistema
- Alarmas y notificaciones

## Consideraciones de Seguridad

- 🔒 Credenciales seguras en Smithery
- 🏠 Acceso solo a red local
- 🔐 Soporte para SSL/TLS
- 🛡️ Validación de entrada

## Pruebas Locales

Para probar localmente antes del despliegue:

```bash
# Instalar dependencias
pip install -r requirements.txt

# Configurar variables de entorno
cp .env.example .env
# Editar .env con tus valores

# Ejecutar servidor
python smithery_server.py
```

## Requisitos

- Python 3.8+
- Controlador UniFi accesible
- Credenciales de administrador UniFi
- Cuenta en Smithery
- Claude Desktop

## Solución de Problemas

### Conexión
- Verificar IP y puerto del controlador
- Confirmar credenciales
- Revisar conectividad de red

### Autenticación
- Validar usuario y contraseña
- Verificar permisos de administrador
- Comprobar configuración SSL

### Smithery
- Revisar logs de despliegue
- Verificar variables de entorno
- Confirmar configuración de puerto

## Documentación Adicional

- [Documentación de UniFi API](https://ubntwiki.com/products/software/unifi-controller/api)
- [Guía de Smithery](https://smithery.ai/docs)
- [Protocolo MCP](https://modelcontextprotocol.io)

## Cómo Contribuir

1. Fork el repositorio
2. Crea una rama para tu feature
3. Commit tus cambios
4. Push a la rama
5. Abre un Pull Request

## Licencia

MIT License - Ver archivo LICENSE para detalles.

---

✨ **¡Tu servidor MCP UniFi está listo para revolucionar la gestión de redes con IA!** ✨