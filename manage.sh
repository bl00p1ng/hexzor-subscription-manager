#!/bin/bash

# ========================================
# Script de Gestión Simple - Nexos Subscription Manager
# Sin PM2, usando systemd directamente
# ========================================

SERVICE_NAME="nexos-subscription"
APP_DIR="$(pwd)"
DB_NAME="hexzor_subscriptions"
DB_USER="hexzor_user"

# Colores para mensajes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Función para mostrar ayuda
show_help() {
    echo "======================================="
    echo "Gestión de Nexos Subscription Manager"
    echo "======================================="
    echo ""
    echo "Comandos disponibles:"
    echo "  start       - Iniciar aplicación"
    echo "  stop        - Detener aplicación"
    echo "  restart     - Reiniciar aplicación"
    echo "  status      - Ver estado del servicio"
    echo "  logs        - Ver logs en tiempo real"
    echo "  enable      - Habilitar inicio automático"
    echo "  disable     - Deshabilitar inicio automático"
    echo "  update      - Actualizar desde Git"
    echo "  backup      - Crear backup de BD"
    echo "  install     - Instalar servicio systemd"
    echo "  test        - Probar aplicación localmente"
    echo ""
    echo "Ejemplos:"
    echo "  $0 start"
    echo "  $0 logs"
    echo "  $0 update"
    echo ""
}

# Función para mensajes con colores
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Función para verificar si el servicio existe
service_exists() {
    systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"
}

# Función para verificar si el usuario tiene permisos sudo
check_sudo() {
    if ! sudo -n true 2>/dev/null; then
        print_error "Este comando requiere permisos sudo"
        exit 1
    fi
}

# Iniciar servicio
start_service() {
    print_info "Iniciando servicio ${SERVICE_NAME}..."
    
    if ! service_exists; then
        print_error "Servicio no instalado. Ejecuta: $0 install"
        exit 1
    fi
    
    check_sudo
    
    if sudo systemctl start "$SERVICE_NAME"; then
        print_success "Servicio iniciado correctamente"
        sleep 2
        sudo systemctl status "$SERVICE_NAME" --no-pager -l
    else
        print_error "Error al iniciar el servicio"
        exit 1
    fi
}

# Detener servicio
stop_service() {
    print_info "Deteniendo servicio ${SERVICE_NAME}..."
    check_sudo
    
    if sudo systemctl stop "$SERVICE_NAME"; then
        print_success "Servicio detenido"
    else
        print_error "Error al detener el servicio"
        exit 1
    fi
}

# Reiniciar servicio
restart_service() {
    print_info "Reiniciando servicio ${SERVICE_NAME}..."
    check_sudo
    
    if sudo systemctl restart "$SERVICE_NAME"; then
        print_success "Servicio reiniciado correctamente"
        sleep 2
        sudo systemctl status "$SERVICE_NAME" --no-pager -l
    else
        print_error "Error al reiniciar el servicio"
        exit 1
    fi
}

# Ver estado del servicio
show_status() {
    print_info "Estado del servicio ${SERVICE_NAME}:"
    echo ""
    
    if service_exists; then
        sudo systemctl status "$SERVICE_NAME" --no-pager -l
        echo ""
        
        # Mostrar si está habilitado para inicio automático
        if systemctl is-enabled "$SERVICE_NAME" >/dev/null 2>&1; then
            print_success "Servicio habilitado para inicio automático"
        else
            print_warning "Servicio NO habilitado para inicio automático"
        fi
        
        # Mostrar puerto si está activo
        if systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
            echo ""
            print_info "Verificando puerto 3001:"
            if netstat -tlnp 2>/dev/null | grep -q ":3001 "; then
                print_success "Aplicación escuchando en puerto 3001"
                local ip=$(curl -s ifconfig.me 2>/dev/null || echo "TU_IP")
                echo "  • API: http://${ip}:3001"
                echo "  • Admin: http://${ip}:3001/admin"
            else
                print_warning "Puerto 3001 no está en uso"
            fi
        fi
    else
        print_error "Servicio no está instalado"
        echo "Ejecuta: $0 install"
    fi
}

# Ver logs en tiempo real
show_logs() {
    if ! service_exists; then
        print_error "Servicio no instalado"
        exit 1
    fi
    
    print_info "Mostrando logs en tiempo real (Ctrl+C para salir):"
    sudo journalctl -f -u "$SERVICE_NAME"
}

# Habilitar inicio automático
enable_service() {
    print_info "Habilitando inicio automático..."
    check_sudo
    
    if sudo systemctl enable "$SERVICE_NAME"; then
        print_success "Servicio habilitado para inicio automático"
    else
        print_error "Error al habilitar el servicio"
        exit 1
    fi
}

# Deshabilitar inicio automático
disable_service() {
    print_info "Deshabilitando inicio automático..."
    check_sudo
    
    if sudo systemctl disable "$SERVICE_NAME"; then
        print_success "Servicio deshabilitado"
    else
        print_error "Error al deshabilitar el servicio"
        exit 1
    fi
}

# Actualizar aplicación desde Git
update_app() {
    print_info "Actualizando aplicación desde Git..."
    
    # Verificar que estamos en un repositorio Git
    if [ ! -d ".git" ]; then
        print_error "Este directorio no es un repositorio Git"
        exit 1
    fi
    
    # Crear backup antes de actualizar
    if service_exists && systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
        backup_database
    fi
    
    # Detener servicio si está corriendo
    if service_exists && systemctl is-active "$SERVICE_NAME" >/dev/null 2>&1; then
        print_info "Deteniendo servicio para actualización..."
        sudo systemctl stop "$SERVICE_NAME"
    fi
    
    # Hacer pull de Git
    print_info "Descargando cambios..."
    if git pull origin main; then
        print_success "Código actualizado"
    else
        print_error "Error al actualizar código"
        # Intentar reiniciar con versión anterior
        if service_exists; then
            sudo systemctl start "$SERVICE_NAME"
        fi
        exit 1
    fi
    
    # Instalar dependencias
    print_info "Instalando dependencias..."
    if npm install; then
        print_success "Dependencias instaladas"
    else
        print_error "Error al instalar dependencias"
        exit 1
    fi
    
    # Reiniciar servicio
    if service_exists; then
        print_info "Reiniciando servicio..."
        sudo systemctl start "$SERVICE_NAME"
        print_success "Aplicación actualizada y reiniciada"
    else
        print_success "Aplicación actualizada (servicio no instalado)"
    fi
}

# Crear backup de base de datos
backup_database() {
    print_info "Creando backup de base de datos..."
    
    local backup_dir="./backups"
    local backup_file="${backup_dir}/nexos_backup_$(date +%Y%m%d_%H%M%S).sql"
    
    # Crear directorio de backups si no existe
    mkdir -p "$backup_dir"
    
    # Verificar que PostgreSQL está disponible
    if ! command -v pg_dump >/dev/null 2>&1; then
        print_error "pg_dump no está disponible"
        exit 1
    fi
    
    # Crear backup
    if pg_dump -h localhost -U "$DB_USER" "$DB_NAME" > "$backup_file" 2>/dev/null; then
        print_success "Backup creado: $backup_file"
        
        # Comprimir si es grande (>10MB)
        if [ $(stat --format=%s "$backup_file" 2>/dev/null || echo 0) -gt 10485760 ]; then
            gzip "$backup_file"
            print_info "Backup comprimido: ${backup_file}.gz"
        fi
        
        # Limpiar backups antiguos (mantener últimos 7)
        ls -t "${backup_dir}"/nexos_backup_*.sql* 2>/dev/null | tail -n +8 | xargs rm -f 2>/dev/null
        print_info "Backups antiguos limpiados"
    else
        print_error "Error al crear backup"
        exit 1
    fi
}

# Instalar servicio systemd
install_service() {
    print_info "Instalando servicio systemd..."
    check_sudo
    
    local service_file="/etc/systemd/system/${SERVICE_NAME}.service"
    local current_user=$(whoami)
    local current_dir="$(pwd)"
    
    # Verificar que existe src/server.js
    if [ ! -f "src/server.js" ]; then
        print_error "No se encontró src/server.js en el directorio actual"
        exit 1
    fi
    
    # Crear archivo de servicio
    print_info "Creando archivo de servicio..."
    sudo tee "$service_file" > /dev/null << EOF
[Unit]
Description=Nexos Subscription Manager
After=network.target postgresql.service
Wants=postgresql.service

[Service]
Type=simple
User=${current_user}
WorkingDirectory=${current_dir}
ExecStart=/usr/bin/node src/server.js
Restart=always
RestartSec=5
Environment=NODE_ENV=production
Environment=PATH=/usr/bin:/usr/local/bin
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nexos-subscription

[Install]
WantedBy=multi-user.target
EOF
    
    # Recargar systemd y habilitar servicio
    sudo systemctl daemon-reload
    
    if sudo systemctl enable "$SERVICE_NAME"; then
        print_success "Servicio instalado y habilitado"
        print_info "Ahora puedes usar: $0 start"
    else
        print_error "Error al instalar el servicio"
        exit 1
    fi
}

# Probar aplicación localmente
test_app() {
    print_info "Probando aplicación localmente..."
    
    if [ ! -f "src/server.js" ]; then
        print_error "No se encontró src/server.js"
        exit 1
    fi
    
    if [ ! -f ".env" ]; then
        print_warning "No se encontró archivo .env"
        print_info "Copiando desde .env.example..."
        
        if [ -f ".env.example" ]; then
            cp .env.example .env
            print_warning "Edita el archivo .env antes de continuar"
            exit 1
        else
            print_error "Tampoco se encontró .env.example"
            exit 1
        fi
    fi
    
    print_info "Ejecutando: npm start"
    print_warning "Presiona Ctrl+C para detener"
    npm start
}

# Procesamiento de comandos
case "${1}" in
    start)
        start_service
        ;;
    stop)
        stop_service
        ;;
    restart)
        restart_service
        ;;
    status)
        show_status
        ;;
    logs)
        show_logs
        ;;
    enable)
        enable_service
        ;;
    disable)
        disable_service
        ;;
    update)
        update_app
        ;;
    backup)
        backup_database
        ;;
    install)
        install_service
        ;;
    test)
        test_app
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        print_error "Comando no reconocido: ${1:-''}"
        echo ""
        show_help
        exit 1
        ;;
esac