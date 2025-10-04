# Hexzor Subscription Manager

## Instrucciones deploy

- Clonar el repositorio en el servidor
- Instalar nvm: `curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash`
- Instalar node 24.7.0 LTS: `nvm install 24.7.0``
- Habilitar node 24.7.9 LTS: `nvm use 24.7.0`
- Instalar dependencias: `npm i`
- Instalar PosgreSQL:
    ```shell
    sudo apt install postgresql postgresql-contrib -y
    sudo systemctl enable postgresql
    sudo systemctl start postgresql
    ```
- Entrar a Postgres: `sudo -u postgres psql`
- Dentro de PostgreSQL, crear usuario y base de datos:
    ```SQL
    CREATE USER hexzor_user WITH ENCRYPTED PASSWORD 'password';
    CREATE DATABASE hexzor_subscriptions OWNER hexzor_user;
    GRANT ALL PRIVILEGES ON DATABASE hexzor_subscriptions TO hexzor_user;
    \q
    ```
- Configurar PostgreSQL para permitir conexiones locales: `sudo nano /etc/postgresql/*/main/pg_hba.conf`
    ```
    # Buscar la línea:
    # local   all             all                                     peer
    # Y cambiarla por:
    # local   all             all                                     md5
    ```
- Reiniciar PostgreSQL: `sudo systemctl restart postgresql`
- Crear archivo `.env`
- Crear Servicio Systemd: `sudo nano /etc/systemd/system/hexzor-subscription.service`
    ```
    [Unit]
    Description=Hexzor Subscription Manager - Sistema de gestión de suscripciones
    After=network.target postgresql.service
    Wants=postgresql.service
    Requires=network.target

    [Service]
    # Configuración del proceso
    Type=simple
    User=dev

    # Directorio de trabajo
    WorkingDirectory=/home/dev/apps/hexzor-subscription-manager

    # Comando para ejecutar la aplicación
    ExecStart=/home/dev/.nvm/versions/node/v24.7.0/bin/node src/server.js

    # Configuración de reinicio
    Restart=always
    RestartSec=5
    StartLimitInterval=60s
    StartLimitBurst=3

    # Variables de entorno
    Environment=NODE_ENV=production
    #Environment=PATH=/usr/bin:/usr/local/bin:/bin
    #Environment=HOME=/home/dev

    # Configuración de logs
    StandardOutput=journal
    StandardError=journal
    SyslogIdentifier=nexos-subscription

    # Configuración de seguridad
    #NoNewPrivileges=true
    #PrivateTmp=true
    #ProtectSystem=strict
    #ProtectHome=true
    #ReadWritePaths=/home/dev/apps/hexzor-subscription-manager

    # Configuración de recursos
    # MemoryLimit=6144M
    TasksMax=50

    # Configuración de señales
    KillMode=mixed
    KillSignal=SIGTERM
    TimeoutStopSec=30

    [Install]
    WantedBy=multi-user.target
    ```
- Recargar systemd: `sudo systemctl daemon-reload`
- Habilitar el servicio: `sudo systemctl enable hexzor-subscription`
- Iniciar el servicio: `sudo systemctl start hexzor-subscription`
- Verificar estado: `sudo systemctl status hexzor-subscription`

## Monitorear/Administrar App

- Ver estado del servicio: `sudo systemctl status hexzor-subscription`
- Ver logs en tiempo real: `sudo journalctl -f -u hexzor-subscription`
- Reiniciar aplicación: `sudo systemctl restart hexzor-subscription`
- Detener aplicación: `sudo systemctl stop hexzor-subscription`
- Iniciar aplicación: `sudo systemctl start hexzor-subscription`
- Ver logs históricos: `sudo journalctl -u hexzor-subscription --lines=100`

## Sistema de Sesión Única por Dispositivo

### Descripción

El sistema garantiza que cada usuario solo pueda usar su cuenta en **un dispositivo a la vez**. Si intenta acceder desde un segundo dispositivo mientras existe una sesión activa en otro, el acceso será bloqueado.

### Funcionamiento

1. **Device Fingerprinting**: Cada dispositivo genera un identificador único basado en hardware (CPU, RAM, MAC address, etc.)
2. **Tabla `active_sessions`**: Registra sesiones activas con constraint `UNIQUE(email, device_fingerprint)`
3. **Validación en tiempo real**: Cada request autenticado verifica que no haya sesiones en otros dispositivos

### Flujo de Usuario

```
Usuario en Dispositivo A → Login exitoso → Sesión activa creada
Usuario en Dispositivo B → Intento de login → ❌ BLOQUEADO (sesión activa en A)
```

El bloqueo persiste hasta que:
- Expire el token (24h)
- Usuario cierre sesión en Dispositivo A
- Admin invalide la sesión manualmente

### API Endpoints Relevantes

| Endpoint | Descripción |
|----------|-------------|
| `POST /api/auth/request-code` | Solicitar código (requiere header `x-device-fingerprint`) |
| `POST /api/auth/verify-code` | Verificar código y crear sesión |
| `DELETE /api/auth/session/logout` | Cerrar sesión actual |
| `DELETE /api/auth/sessions/all` | Cerrar TODAS las sesiones (emergencia) |
| `GET /api/auth/sessions` | Ver sesiones activas del usuario |

### Respuestas de Error

**Sesión activa en otro dispositivo:**
```json
{
  "success": false,
  "error": "Ya existe una sesión activa en otro dispositivo",
  "code": "MULTIPLE_DEVICE_BLOCKED",
  "blockedUntil": "2025-09-30T15:30:00.000Z",
  "message": "Solo puedes usar tu cuenta en un dispositivo a la vez..."
}
```

### Implementación en Cliente

El cliente (Cookies Hexzor) debe:

1. **Generar device fingerprint** usando `node-machine-id`
2. **Enviar header** `x-device-fingerprint` en todos los requests
3. **Manejar errores** `MULTIPLE_DEVICE_BLOCKED` mostrando mensaje claro

Ver guía completa en [DEVICE_FINGERPRINTING_CLIENT.md](DEVICE_FINGERPRINTING_CLIENT.md)

### Administración

**Consultar sesiones activas:**
```sql
SELECT email, device_fingerprint, ip_address, last_activity, expires_at
FROM active_sessions WHERE expires_at > NOW();
```

**Invalidar sesión de usuario específico:**
```javascript
await db.invalidateSession('user@example.com');
```

**Ver bloqueos recientes:**
```sql
SELECT email, ip_address, error_message, created_at
FROM access_logs
WHERE action = 'BLOCKED_MULTIPLE_DEVICE_ATTEMPT'
ORDER BY created_at DESC LIMIT 50;
```

### Mantenimiento Automático

- **Limpieza de sesiones expiradas**: Cada 30 minutos automáticamente
- **Logs de auditoría**: Todos los eventos registrados en `access_logs`
- **Backups**: Incluir tabla `active_sessions` en respaldos de BD