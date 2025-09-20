#!/bin/bash

# ========================================
# Script de Despliegue Automatizado
# Hexzor Subscription Manager
# ========================================

set -e  # Salir en caso de error

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables de configuración
APP_NAME="hexzor-subscription-manager"
APP_DIR="/var/www/${APP_NAME}"
SERVICE_USER="ubuntu"
DB_NAME="hexzor_subscriptions"
DB_USER="hexzor_user"
BACKUP_DIR="/var/backups/${APP_NAME}"

# Función para imprimir mensajes con colores
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Función para verificar si un comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Función para verificar servicios
check_service() {
    if systemctl is-active --quiet "$1"; then
        print_success "$1 está ejecutándose"
        return 0
    else
        print_error "$1 no está ejecutándose"
        return 1
    fi
}

# Función para crear directorio con permisos
create_directory() {
    local dir=$1
    local owner=${2:-$SERVICE_USER}
    
    if [ ! -d "$dir" ]; then
        print_status "Creando directorio: $dir"
        sudo mkdir -p "$dir"
        sudo chown "$owner:$owner" "$dir"
        print_success "Directorio creado: $dir"
    else
        print_success "Directorio ya existe: $dir"
    fi
}

# Función para generar contraseña aleatoria
generate_password() {
    openssl rand -base64 32 | tr -d "=+/" | cut -c1-25
}

# Función para hacer backup de la base de datos
backup_database() {
    if [ "$DB_EXISTS" = true ]; then
        print_status "Creando backup de la base de datos..."
        local backup_file="${BACKUP_DIR}/db_backup_$(date +%Y%m%d_%H%M%S).sql"
        
        create_directory "$BACKUP_DIR"
        
        sudo -u postgres pg_dump "$DB_NAME" > "$backup_file" 2>/dev/null || {
            print_warning "No se pudo crear backup de la BD (puede que no exista aún)"
        }
        
        if [ -f "$backup_file" ]; then
            print_success "Backup creado: $backup_file"
        fi
    fi
}

print_status "🚀 Iniciando despliegue de ${APP_NAME}..."

# ========================================
# 1. VERIFICACIONES PREVIAS
# ========================================

print_status "📋 Verificando requisitos del sistema..."

# Verificar si es root o tiene sudo
if [ "$EUID" -eq 0 ]; then
    print_warning "Ejecutándose como root. Se recomienda usar sudo en su lugar."
fi

# Verificar comandos necesarios
REQUIRED_COMMANDS=("node" "npm" "git" "systemctl")
for cmd in "${REQUIRED_COMMANDS[@]}"; do
    if command_exists "$cmd"; then
        print_success "$cmd está instalado"
    else
        print_error "$cmd no está instalado"
        exit 1
    fi
done

# Verificar versión de Node.js
NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -ge 18 ]; then
    print_success "Node.js versión: $(node --version)"
else
    print_error "Node.js debe ser versión 18 o superior. Versión actual: $(node --version)"
    exit 1
fi

# Verificar PM2
if command_exists "pm2"; then
    print_success "PM2 está instalado: $(pm2 --version)"
else
    print_error "PM2 no está instalado. Instalando..."
    sudo npm install -g pm2
    print_success "PM2 instalado"
fi

# ========================================
# 2. CONFIGURACIÓN DE POSTGRESQL
# ========================================

print_status "🗄️ Configurando PostgreSQL..."

# Verificar si PostgreSQL está instalado
if command_exists "psql"; then
    print_success "PostgreSQL está instalado"
    
    # Verificar si el servicio está ejecutándose
    if check_service "postgresql"; then
        print_success "PostgreSQL está ejecutándose"
    else
        print_status "Iniciando PostgreSQL..."
        sudo systemctl start postgresql
        sudo systemctl enable postgresql
    fi
else
    print_error "PostgreSQL no está instalado. Instalando..."
    sudo apt update
    sudo apt install -y postgresql postgresql-contrib
    sudo systemctl start postgresql
    sudo systemctl enable postgresql
    print_success "PostgreSQL instalado y configurado"
fi

# Verificar si la base de datos existe
if sudo -u postgres psql -lqt | cut -d \| -f 1 | grep -qw "$DB_NAME"; then
    print_success "Base de datos '$DB_NAME' ya existe"
    DB_EXISTS=true
else
    print_status "Creando base de datos '$DB_NAME'..."
    DB_EXISTS=false
fi

# Verificar si el usuario de BD existe
if sudo -u postgres psql -t -c '\du' | cut -d \| -f 1 | grep -qw "$DB_USER"; then
    print_success "Usuario de BD '$DB_USER' ya existe"
    USER_EXISTS=true
else
    print_status "Creando usuario de BD '$DB_USER'..."
    USER_EXISTS=false
fi

# Crear usuario y base de datos si no existen
if [ "$USER_EXISTS" = false ] || [ "$DB_EXISTS" = false ]; then
    DB_PASSWORD=$(generate_password)
    
    if [ "$USER_EXISTS" = false ]; then
        sudo -u postgres createuser --createdb --pwprompt "$DB_USER" << EOF
$DB_PASSWORD
$DB_PASSWORD
EOF
        print_success "Usuario '$DB_USER' creado"
    fi
    
    if [ "$DB_EXISTS" = false ]; then
        sudo -u postgres createdb -O "$DB_USER" "$DB_NAME"
        print_success "Base de datos '$DB_NAME' creada"
    fi
    
    # Guardar credenciales para el archivo .env
    DB_PASSWORD_NEW="$DB_PASSWORD"
else
    print_status "Usando credenciales existentes de la base de datos"
fi

# ========================================
# 3. CONFIGURACIÓN DE DIRECTORIOS
# ========================================

print_status "📁 Configurando directorios..."

# Crear directorios necesarios
create_directory "$APP_DIR"
create_directory "$APP_DIR/logs"
create_directory "$BACKUP_DIR"

# ========================================
# 4. DESPLIEGUE DE LA APLICACIÓN
# ========================================

print_status "📦 Desplegando aplicación..."

# Navegar al directorio de la app
cd "$APP_DIR"

# Hacer backup si ya existe una versión
if [ -f "package.json" ]; then
    print_status "Haciendo backup de la aplicación existente..."
    backup_database
    
    # Detener PM2 si está corriendo
    if pm2 list | grep -q "$APP_NAME"; then
        print_status "Deteniendo aplicación en PM2..."
        pm2 stop "$APP_NAME" || true
        pm2 delete "$APP_NAME" || true
    fi
fi

# Actualizar código desde git (asume que ya se clonó)
if [ -d ".git" ]; then
    print_status "Actualizando código desde Git..."
    git fetch origin
    git reset --hard origin/main
    git clean -fd
else
    print_error "No se encuentra repositorio Git. Asegúrate de clonar el proyecto primero."
    exit 1
fi

# ========================================
# 5. INSTALACIÓN DE DEPENDENCIAS
# ========================================

print_status "📋 Instalando dependencias..."

# Limpiar node_modules si existe
if [ -d "node_modules" ]; then
    print_status "Limpiando node_modules existente..."
    rm -rf node_modules package-lock.json
fi

# Instalar dependencias
npm ci --production --silent

print_success "Dependencias instaladas"

# ========================================
# 6. CONFIGURACIÓN DE VARIABLES DE ENTORNO
# ========================================

print_status "⚙️ Configurando variables de entorno..."

# Crear archivo .env si no existe
if [ ! -f ".env" ]; then
    print_status "Creando archivo .env..."
    
    # Generar secretos
    JWT_SECRET=$(generate_password)
    
    cat > .env << EOF
# Configuración de Producción - Hexzor Subscription Manager
NODE_ENV=production
PORT=3001

# Base de Datos PostgreSQL
DATABASE_URL=postgresql://${DB_USER}:${DB_PASSWORD_NEW:-'TU_PASSWORD_AQUI'}@localhost:5432/${DB_NAME}

# JWT
JWT_SECRET=${JWT_SECRET}

# Email (SMTP) - Configurar según tu proveedor
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_SECURE=false
SMTP_USER=tu-email@gmail.com
SMTP_PASS=tu-password-de-aplicacion
EMAIL_FROM=noreply@hexzor.com
EMAIL_FROM_NAME=Hexzor Support

# Configuración de Rate Limiting
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100

# Configuración de Seguridad
TRUST_PROXY=1

# URLs y CORS
FRONTEND_URL=http://$(curl -s ifconfig.me):3001
ADMIN_PANEL_URL=http://$(curl -s ifconfig.me):3001/admin

# Logs
LOG_LEVEL=info
LOG_TO_FILE=true
EOF

    print_success "Archivo .env creado"
    print_warning "⚠️  IMPORTANTE: Configura las variables de email en .env"
    print_warning "⚠️  Actualiza la contraseña de BD si usas una existente"
else
    print_success "Archivo .env ya existe"
fi

# Asegurar permisos del archivo .env
chmod 600 .env
chown "$SERVICE_USER:$SERVICE_USER" .env

# ========================================
# 7. CONFIGURACIÓN DE FIREWALL
# ========================================

print_status "🔥 Configurando firewall..."

# Verificar si ufw está instalado
if command_exists "ufw"; then
    # Permitir puerto de la aplicación
    sudo ufw allow 3001/tcp comment "Hexzor Subscription Manager"
    
    # Verificar estado del firewall
    if sudo ufw status | grep -q "Status: active"; then
        print_success "Firewall configurado - Puerto 3001 abierto"
    else
        print_warning "Firewall no está activo. Para activarlo: sudo ufw enable"
    fi
else
    print_warning "UFW no está instalado. Se recomienda configurar un firewall."
fi

# ========================================
# 8. CONFIGURACIÓN INICIAL DE LA APP
# ========================================

print_status "🔧 Configuración inicial de la aplicación..."

# Ejecutar setup de administrador si existe
if [ -f "src/setup/createAdmin.js" ]; then
    print_status "Configurando administrador inicial..."
    print_warning "Este paso puede requerir intervención manual para crear el admin"
    
    # Permitir al usuario configurar el admin
    echo ""
    echo "========================================="
    echo "CONFIGURACIÓN DE ADMINISTRADOR"
    echo "========================================="
    echo "Se ejecutará el script de creación de administrador."
    echo "Sigue las instrucciones en pantalla."
    echo ""
    read -p "Presiona ENTER para continuar..."
    
    npm run setup
fi

# ========================================
# 9. INICIO CON PM2
# ========================================

print_status "🚀 Iniciando aplicación con PM2..."

# Asegurar que el usuario actual puede escribir en logs
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"

# Iniciar con PM2
pm2 start ecosystem.config.js --env production

# Guardar configuración de PM2
pm2 save

# Configurar PM2 para inicio automático
if ! pm2 startup | grep -q "already"; then
    print_status "Configurando PM2 para inicio automático..."
    pm2 startup | grep -E "sudo|pm2" | tail -1 | bash
    pm2 save
fi

print_success "Aplicación iniciada con PM2"

# ========================================
# 10. VERIFICACIONES FINALES
# ========================================

print_status "🔍 Verificaciones finales..."

# Verificar que la aplicación esté corriendo
sleep 5

if pm2 list | grep -q "$APP_NAME.*online"; then
    print_success "Aplicación está corriendo en PM2"
else
    print_error "La aplicación no está corriendo correctamente"
    pm2 logs "$APP_NAME" --lines 20
    exit 1
fi

# Verificar conectividad HTTP
SERVER_IP=$(curl -s ifconfig.me)
print_status "Verificando conectividad HTTP..."

if curl -f -s "http://localhost:3001/health" > /dev/null; then
    print_success "Aplicación responde correctamente"
else
    print_warning "La aplicación puede no estar respondiendo aún. Verificando logs..."
    pm2 logs "$APP_NAME" --lines 10
fi

# ========================================
# 11. INFORMACIÓN FINAL
# ========================================

echo ""
echo "========================================="
echo "🎉 DESPLIEGUE COMPLETADO"
echo "========================================="
echo ""
echo "📋 Información del despliegue:"
echo "   • Aplicación: $APP_NAME"
echo "   • Directorio: $APP_DIR"
echo "   • Usuario: $SERVICE_USER"
echo "   • Base de datos: $DB_NAME"
echo ""
echo "🌐 URLs de acceso:"
echo "   • Panel Admin: http://$SERVER_IP:3001/admin"
echo "   • API Health: http://$SERVER_IP:3001/health"
echo "   • API Status: http://$SERVER_IP:3001/api/status"
echo ""
echo "📊 Comandos útiles de PM2:"
echo "   • Ver estado: pm2 status"
echo "   • Ver logs: pm2 logs $APP_NAME"
echo "   • Reiniciar: pm2 restart $APP_NAME"
echo "   • Detener: pm2 stop $APP_NAME"
echo "   • Monitor: pm2 monit"
echo ""
echo "📁 Archivos importantes:"
echo "   • Configuración: $APP_DIR/.env"
echo "   • Logs: $APP_DIR/logs/"
echo "   • Backups: $BACKUP_DIR"
echo ""

if [ -n "$DB_PASSWORD_NEW" ]; then
    echo "🔐 IMPORTANTE - Credenciales de BD (guárdalas):"
    echo "   • Usuario: $DB_USER"
    echo "   • Contraseña: $DB_PASSWORD_NEW"
    echo "   • Base de datos: $DB_NAME"
    echo ""
fi

echo "⚠️  RECORDATORIOS:"
echo "   • Configura las variables de email en: $APP_DIR/.env"
echo "   • Actualiza las URLs si usas un dominio"
echo "   • Configura SSL/HTTPS para producción"
echo "   • Programa backups automáticos"
echo ""

print_success "¡Despliegue completado exitosamente!"