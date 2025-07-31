# 🔧 Solución de Problemas - Smithery

## Error: "Unexpected internal error or timeout"

### Problema Identificado
El error indica que hubo un problema durante el despliegue del contenedor Docker en Smithery.

### Soluciones Implementadas

#### 1. ✅ Dockerfile Simplificado
- Cambiado de Python 3.12 a 3.11 (más estable)
- Removido health check complejo
- Removido usuario no-root (puede causar problemas de permisos)
- Simplificada la copia de archivos

#### 2. ✅ Servidor Simplificado
- Removido FastAPI y uvicorn innecesarios
- Simplificado el manejo de errores
- Mejorado el logging para debugging
- Configuración de entorno más robusta

#### 3. ✅ Dependencias Optimizadas
- Removidas dependencias innecesarias (FastAPI, uvicorn)
- Mantenidas solo las dependencias esenciales para MCP

### Pasos para Redesplegar

1. **Verificar Commit Actual**
   ```
   Commit: a84881743e250a39a780022d46bcacb58e5df38e
   Mensaje: "Fix Smithery deployment issues - simplify Docker and server setup"
   ```

2. **En Smithery:**
   - Ve a tu proyecto `mcp-unifi`
   - Haz clic en "Redeploy" o "Deploy" nuevamente
   - Smithery detectará automáticamente los cambios

3. **Variables de Entorno Requeridas:**
   ```
   unifiRouterIp=192.168.1.1
   unifiUsername=admin
   unifiPassword=tu_password_real
   unifiPort=443
   unifiVerifySsl=false
   ```

### Verificación del Despliegue

Una vez desplegado exitosamente, deberías ver en los logs:
```
Starting UniFi MCP Server for Smithery on 0.0.0.0:3000
UniFi Router IP: 192.168.1.1
UniFi Port: 443
SSL Verification: false
```

### Configuración en Claude Desktop

Después del despliegue exitoso:

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

### Problemas Comunes y Soluciones

#### Error de Conexión a UniFi
- **Problema**: No puede conectar al controlador UniFi
- **Solución**: Verificar IP, usuario y contraseña en variables de entorno

#### Error de Puerto
- **Problema**: Puerto no disponible
- **Solución**: Smithery maneja automáticamente el puerto, no modificar

#### Error de SSL
- **Problema**: Certificados SSL inválidos
- **Solución**: Configurar `unifiVerifySsl=false`

### Logs de Debugging

Para ver logs detallados en Smithery:
1. Ve a la pestaña "Logs" en tu proyecto
2. Busca mensajes que comiencen con "UniFi MCP Server"
3. Reporta cualquier error específico

### Contacto para Soporte

Si el problema persiste:
1. Copia los logs completos de Smithery
2. Verifica que todas las variables de entorno estén configuradas
3. Asegúrate de que el controlador UniFi esté accesible desde internet

---

**Última actualización**: Commit a84881743e250a39a780022d46bcacb58e5df38e
**Estado**: ✅ Listo para redespliegue