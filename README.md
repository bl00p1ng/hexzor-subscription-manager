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
    ReadWritePaths=/home/dev/apps/hexzor-subscription-manager

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