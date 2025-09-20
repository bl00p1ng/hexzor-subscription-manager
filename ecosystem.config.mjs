/**
 * Configuración de PM2 para Hexzor Subscription Manager
 * Este archivo define la aplicación en producción con PM2
 */
export default {
    apps: [{
        // Identificación de la aplicación
        name: 'hexzor-subscription-manager',
        script: 'src/server.js',
        
        // Configuración de ejecución
        instances: 1, // Usar 1 instancia para evitar problemas con sesiones
        exec_mode: 'fork', // Modo fork para aplicaciones que no son stateless
        
        // Variables de entorno
        env: {
            NODE_ENV: 'development',
            PORT: 3001
        },
        env_production: {
            NODE_ENV: 'production',
            PORT: 3001
        },
        
        // Configuración de logs
        log_file: './logs/app.log',
        out_file: './logs/out.log',
        error_file: './logs/error.log',
        log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
        log_type: 'json',
        
        // Configuración de reinicio automático
        watch: false, // No vigilar archivos en producción
        ignore_watch: ['node_modules', 'logs', '*.log'],
        max_memory_restart: '500M',
        
        // Configuración de reinicio en caso de fallo
        autorestart: true,
        max_restarts: 5,
        min_uptime: '10s',
        
        // Configuración de cluster (deshabilitada para esta app)
        kill_timeout: 5000,
        wait_ready: true,
        listen_timeout: 10000,
        
        // Scripts de ciclo de vida
        pre_setup: 'echo "Preparando aplicación..."',
        post_setup: 'echo "Aplicación configurada"',
        
        // Configuración adicional
        merge_logs: true,
        time: true,
        
        // Variables de entorno específicas del servidor
        env_file: '.env'
    }],
};