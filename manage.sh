#!/bin/bash

# ========================================
# Script de Gestión - Hexzor Subscription Manager
# Comandos útiles para administrar la aplicación
# ========================================

APP_NAME="hexzor-subscription-manager"
APP_DIR="/var/www/${APP_NAME}"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_help() {
    echo "======================================"
    echo "Gestión de Hexzor Subscription Manager"
    echo "======================================"
    echo ""
    echo "Uso: $0 [comando]"
    echo ""
    echo "Comandos disponibles:"
    echo "  status      - Ver estado de la aplicación"
    echo "  logs        - Ver logs en tiempo real"
    echo "  restart     - Reiniciar aplicación"
    echo "  stop        - Detener aplicación"
    echo "  start       - Iniciar aplicación"
    echo "  update      - Actualizar desde Git y reiniciar"
    echo "  backup      - Crear backup de la base de datos"
    echo "  restore     - Restaurar backup (requiere archivo)"
    echo "  env         - Editar variables de entorno"
    echo "  admin       - Crear nuevo administrador"
    echo "  health      - Verificar salud del sistema"
    echo "  ip          - Mostrar URLs de acceso"
    echo ""
    echo "Ejemplos:"
    echo "  $0 status          # Ver estado"
    echo "  $0 logs            # Ver logs"
    echo "  $0 update          # Actualizar app"
    echo "  $0 restore backup.sql  # Restaurar BD"
    echo ""
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

check_app_dir() {
    if [ ! -d "$APP_DIR" ]; then
        print_error "Directorio de la aplicación no encontrado: $APP_DIR"
        exit 1
    fi
}

show_status() {
    print_status "Estado de la aplicación:"
    pm2 status "$APP_NAME"
    echo ""
    
    print_status "Uso de recursos:"
    pm2 show "$APP_NAME" 2>/dev/null | grep -E "(cpu|memory|uptime|restarts)"
    echo ""
    
    print_status "Últimas líneas del log:"
    pm2 logs "$APP_NAME" --lines 5 --nostream
}

show_logs() {
    print_status "Mostrando logs en tiempo real (Ctrl+C para salir):"
    pm2 logs "$APP_NAME" --lines 50
}

restart_app() {
    print_status "Reiniciando aplicación..."
    pm2 restart "$APP_NAME"
    
    if [ $? -eq 0 ]; then
        print_success "Aplicación reiniciada"
        sleep 2
        show_status
    else
        print_error "Error al reiniciar la aplicación"
        exit 1
    fi
}

stop_app() {
    print_status "Deteniendo aplicación..."
    pm2 stop "$APP_NAME"
    
    if [ $? -eq 0 ]; then
        print_success "Aplicación detenida"
    else
        print_error "Error al detener la aplicación"
        exit 1
    fi
}

start_app() {
    print_status "Iniciando aplicación..."
    cd "$APP_DIR"
    pm2 start ecosystem.config.js --env production
    
    if [ $? -eq 0 ]; then
        print_success "Aplicación iniciada"
        sleep 2
        show_status
    else
        print_error "Error al iniciar la aplicación"
        exit 1
    fi
}

update_app() {
    check_app_dir
    
    print_status "Actualizando aplicación desde Git..."
    cd "$APP_DIR"
    
    # Verificar que hay cambios
    git fetch origin
    
    if git diff HEAD origin/main --quiet; then
        print_success "La aplicación ya está actualizada"
        return 0
    fi
    
    # Hacer backup antes de actualizar
    backup_database
    
    # Detener aplicación
    print_status "Deteniendo aplicación para actualización..."
    pm2 stop "$APP_NAME" 2>/dev/null || true
    
    # Actualizar código
    print_status "Descargando últimos cambios..."
    git reset --hard origin/main
    git clean -fd
    
    # Instalar dependencias
    print_status "Actualizando dependencias..."
    npm ci --production --silent
    
    # Reiniciar aplicación
    print_status "Reiniciando aplicación..."
    pm2 start ecosystem.config.js --env production
    
    if [ $? -eq 0 ]; then
        print_success "Aplicación actualizada y reiniciada"
        sleep 3
        show_status
    else
        print_error "Error al reiniciar tras actualización"
        exit 1
    fi
}

backup_database() {
    DB_NAME="hexzor_subscriptions"
    BACKUP_DIR="/var/backups/${APP_NAME}"
    BACKUP_FILE="${BACKUP_DIR}/backup_$(date +%Y%m%d_%H%M%S).sql"
    
    print_status "Creando backup de la base de datos..."
    
    mkdir -p "$BACKUP_DIR"
    
    if sudo -u postgres pg_dump "$DB_NAME" > "$BACKUP_FILE" 2>/dev/null; then
        print_success "Backup creado: $BACKUP_FILE"
        
        # Mantener solo los últimos 10 backups
        ls -t "${BACKUP_DIR}"/backup_*.sql | tail -n +11 | xargs -r rm
        print_status "Backups antiguos limpiados (manteniendo 10)"
    else
        print_error "Error al crear backup de la base de datos"
        exit 1
    fi
}

restore_database() {
    local backup_file="$1"
    DB_NAME="hexzor_subscriptions"
    
    if [ -z "$backup_file" ]; then
        print_error "Debe especificar el archivo de backup"
        echo "Uso: $0 restore /ruta/al/backup.sql"
        exit 1
    fi
    
    if [ ! -f "$backup_file" ]; then
        print_error "Archivo de backup no encontrado: $backup_file"
        exit 1
    fi
    
    print_warning "⚠️  Esta operación sobrescribirá la base de datos actual"
    read -p "¿Continuar? (y/N): " -n 1 -r
    echo
    
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_status "Operación cancelada"
        exit 0
    fi
    
    # Crear backup actual antes de restaurar
    backup_database
    
    print_status "Restaurando base de datos desde: $backup_file"
    
    # Detener aplicación
    pm2 stop "$APP_NAME" 2>/dev/null || true
    
    # Restaurar
    if sudo -u postgres psql "$DB_NAME" < "$backup_file" 2>/dev/null; then
        print_success "Base de datos restaurada"
        
        # Reiniciar aplicación
        pm2 start ecosystem.config.js --env production
        print_success "Aplicación reiniciada"
    else
        print_error "Error al restaurar la base de datos"
        exit 1
    fi
}

edit_env() {
    check_app_dir
    
    local env_file="${APP_DIR}/.env"
    
    if [ ! -f "$env_file" ]; then
        print_error "Archivo .env no encontrado: $env_file"
        exit 1
    fi
    
    print_status "Editando variables de entorno..."
    print_warning "Recuerda reiniciar la aplicación después de los cambios"
    
    # Usar el editor preferido del usuario
    local editor="${EDITOR:-nano}"
    
    sudo -u ubuntu "$editor" "$env_file"
    
    read -p "¿Reiniciar la aplicación ahora? (y/N): " -n 1 -r
    echo
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        restart_app
    fi
}

create_admin() {
    check_app_dir
    
    print_status "Creando nuevo administrador..."
    cd "$APP_DIR"
    
    if [ -f "src/setup/createAdmin.js" ]; then
        npm run setup
    else
        print_error "Script de creación de admin no encontrado"
        exit 1
    fi
}

check_health() {
    print_status "Verificando salud del sistema..."
    echo ""
    
    # Verificar PM2
    if pm2 list | grep -q "$APP_NAME.*online"; then
        print_success "PM2: Aplicación ejecutándose"
    else
        print_error "PM2: Aplicación no está ejecutándose"
    fi
    
    # Verificar PostgreSQL
    if systemctl is-active --quiet postgresql; then
        print_success "PostgreSQL: Servicio activo"
    else
        print_error "PostgreSQL: Servicio inactivo"
    fi
    
    # Verificar conectividad HTTP
    if curl -f -s "http://localhost:3001/health" > /dev/null; then
        print_success "HTTP: Aplicación responde"
    else
        print_error "HTTP: Aplicación no responde"
    fi
    
    # Verificar espacio en disco
    local disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$disk_usage" -lt 80 ]; then
        print_success "Disco: ${disk_usage}% usado"
    else
        print_warning "Disco: ${disk_usage}% usado (considerar limpieza)"
    fi
    
    # Verificar memoria
    local mem_usage=$(free | grep Mem | awk '{printf "%.0f", $3/$2 * 100}')
    if [ "$mem_usage" -lt 80 ]; then
        print_success "Memoria: ${mem_usage}% usada"
    else
        print_warning "Memoria: ${mem_usage}% usada"
    fi
    
    echo ""
    print_status "Logs recientes de la aplicación:"
    pm2 logs "$APP_NAME" --lines 3 --nostream 2>/dev/null || echo "No hay logs disponibles"
}

show_ip() {
    local server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "NO_DISPONIBLE")
    
    echo "======================================"
    echo "URLs de Acceso"
    echo "======================================"
    echo ""
    echo "🌐 IP del servidor: $server_ip"
    echo ""
    echo "📱 Panel de Administración:"
    echo "   http://$server_ip:3001/admin"
    echo ""
    echo "🔧 API Endpoints:"
    echo "   • Health Check: http://$server_ip:3001/health"
    echo "   • Status: http://$server_ip:3001/api/status"
    echo "   • Auth: http://$server_ip:3001/api/auth"
    echo ""
    echo "📊 Monitoreo:"
    echo "   • PM2 Web: pm2 web (puerto 9615)"
    echo ""
    
    if [ "$server_ip" = "NO_DISPONIBLE" ]; then
        print_warning "No se pudo obtener la IP pública"
        echo "IP local: $(hostname -I | awk '{print $1}')"
    fi
}

# Función para mostrar estadísticas avanzadas
show_advanced_status() {
    echo "======================================"
    echo "Estadísticas Avanzadas"
    echo "======================================"
    echo ""
    
    # Información del sistema
    print_status "Sistema:"
    echo "  • SO: $(lsb_release -d 2>/dev/null | cut -f2 || uname -s)"
    echo "  • Kernel: $(uname -r)"
    echo "  • Uptime: $(uptime -p 2>/dev/null || uptime)"
    echo ""
    
    # Información de Node.js
    print_status "Runtime:"
    echo "  • Node.js: $(node --version)"
    echo "  • NPM: $(npm --version)"
    echo "  • PM2: $(pm2 --version)"
    echo ""
    
    # Información de la aplicación
    if [ -f "$APP_DIR/package.json" ]; then
        local app_version=$(grep '"version"' "$APP_DIR/package.json" | cut -d'"' -f4)
        print_status "Aplicación:"
        echo "  • Versión: $app_version"
        echo "  • Directorio: $APP_DIR"
        echo "  • Proceso: $APP_NAME"
        echo ""
    fi
    
    # Estadísticas de PM2
    print_status "PM2 Estadísticas:"
    pm2 show "$APP_NAME" 2>/dev/null | grep -E "(uptime|restart|cpu|memory)" | sed 's/^/  • /'
    echo ""
    
    # Conexiones de red
    print_status "Conexiones de red (puerto 3001):"
    local connections=$(netstat -an 2>/dev/null | grep ":3001" | wc -l)
    echo "  • Conexiones activas: $connections"
    echo ""
}

# Función principal
main() {
    case "$1" in
        "status")
            show_status
            ;;
        "status-advanced")
            show_advanced_status
            ;;
        "logs")
            show_logs
            ;;
        "restart")
            restart_app
            ;;
        "stop")
            stop_app
            ;;
        "start")
            start_app
            ;;
        "update")
            update_app
            ;;
        "backup")
            backup_database
            ;;
        "restore")
            restore_database "$2"
            ;;
        "env")
            edit_env
            ;;
        "admin")
            create_admin
            ;;
        "health")
            check_health
            ;;
        "ip")
            show_ip
            ;;
        "help"|"-h"|"--help")
            print_help
            ;;
        "")
            print_help
            ;;
        *)
            print_error "Comando desconocido: $1"
            echo ""
            print_help
            exit 1
            ;;
    esac
}

# Verificar que PM2 esté disponible
if ! command -v pm2 > /dev/null; then
    print_error "PM2 no está instalado o no está en el PATH"
    exit 1
fi

# Ejecutar función principal
main "$@"