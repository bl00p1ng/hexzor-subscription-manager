import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cookieParser from 'cookie-parser';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import dotenv from 'dotenv';

// Importar servicios y rutas
import PostgreSQLManager from './database/PostgreSQLManager.js';
import EmailService from './services/EmailService.js';
import authRoutes from './routes/auth.js';
import adminRoutes from './routes/admin.js';
import adminPanelRoutes from './routes/admin-panel.js';
import { handleExpiredSessions } from './middleware/sessionHandler.js';

// Configuración de variables de entorno
dotenv.config();

// Configurar __dirname para ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

/**
 * Servidor principal del sistema de autenticación
 * Maneja autenticación de usuarios y panel de administración
 */
class AuthServer {
    constructor() {
        this.app = express();
        this.port = process.env.PORT || 3001;
        this.db = null;
        this.emailService = null;
    }

    /**
     * Inicializa el servidor y sus dependencias
     */
    async initialize() {
        try {
            console.log('🚀 Iniciando servidor de autenticación...');

            // Verificar variables de entorno críticas
            this.validateEnvironment();

            // Inicializar base de datos
            this.db = new PostgreSQLManager();
            await this.db.initialize();

            // Inicializar servicio de email
            this.emailService = new EmailService();
            await this.emailService.initialize();

            // Configurar middleware
            this.setupMiddleware();

            // Configurar rutas
            this.setupRoutes();

            // Servir archivos estáticos del panel admin
            this.setupStaticFiles();

            // Manejo de errores
            this.setupErrorHandling();

            // Hacer servicios disponibles globalmente
            this.app.locals.db = this.db;
            this.app.locals.emailService = this.emailService;

            console.log('✅ Servidor inicializado correctamente');

        } catch (error) {
            console.error('❌ Error inicializando servidor:', error.message);
            process.exit(1);
        }
    }

    /**
     * Valida que las variables de entorno necesarias estén configuradas
     */
    validateEnvironment() {
        const required = ['JWT_SECRET'];
        const missing = required.filter(key => !process.env[key]);

        if (missing.length > 0) {
            throw new Error(`Variables de entorno faltantes: ${missing.join(', ')}`);
        }

        // Advertencias para configuraciones opcionales
        if (!process.env.SMTP_USER) {
            console.warn('⚠️ SMTP_USER no configurado - emails no funcionarán');
        }

        if (!process.env.SMTP_PASS) {
            console.warn('⚠️ SMTP_PASS no configurado - emails no funcionarán');
        }
    }

    /**
     * Configura middleware de seguridad y utilidades
     */
    setupMiddleware() {
        // Helmet para seguridad
        this.app.use(helmet({
            contentSecurityPolicy: {
                directives: {
                    defaultSrc: ["'self'"],
                    scriptSrc: ["'self'", "'unsafe-inline'"],
                    styleSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
                    imgSrc: ["'self'", "data:", "https:"],
                    connectSrc: ["'self'"]
                }
            }
        }));

        // CORS configurado
        this.app.use(cors({
            origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
            credentials: true,
            methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
            allowedHeaders: ['Content-Type', 'Authorization']
        }));

        // Rate limiting global
        const globalLimiter = rateLimit({
            windowMs: 15 * 60 * 1000, // 15 minutos
            max: 1000, // 1000 requests por IP
            message: {
                error: 'Demasiadas solicitudes desde esta IP. Intenta más tarde.'
            },
            standardHeaders: true,
            legacyHeaders: false
        });
        this.app.use(globalLimiter);

        // Parsear JSON y cookies
        this.app.use(express.json({ limit: '10mb' }));
        this.app.use(express.urlencoded({ extended: true, limit: '10mb' }));
        this.app.use(cookieParser());

        // Trust proxy para obtener IP real
        this.app.set('trust proxy', 1);

        // Middleware de logging
        this.app.use((req, res, next) => {
            const timestamp = new Date().toISOString();
            console.log(`[${timestamp}] ${req.method} ${req.path} - IP: ${req.ip}`);
            next();
        });
    }

    /**
     * Configura las rutas de la API
     */
    setupRoutes() {
        // Ruta raíz - página de información
        this.app.get('/', (req, res) => {
            res.sendFile(join(__dirname, 'public', 'index.html'));
        });

        // Ruta de health check
        this.app.get('/health', (req, res) => {
            res.json({
                success: true,
                message: 'Servidor funcionando correctamente',
                timestamp: new Date().toISOString(),
                services: {
                    database: !this.db,
                    email: this.emailService.isConfigured()
                }
            });
        });

        // Rutas de autenticación
        this.app.use('/api/auth', authRoutes);

        // Rutas de administración
        this.app.use('/api/admin', adminRoutes);

        // Rutas del panel de administración
        this.app.use('/admin', handleExpiredSessions);
        this.app.use('/admin', adminPanelRoutes);

        // Ruta para obtener información del servidor
        this.app.get('/api/status', async (req, res) => {
            try {
                const emailStatus = this.emailService.getStatus();
                
                res.json({
                    success: true,
                    data: {
                        server: 'Hexzor Auth Backend',
                        version: '1.0.0',
                        timestamp: new Date().toISOString(),
                        environment: process.env.NODE_ENV || 'development',
                        services: {
                            database: {
                                connected: !!this.db,
                                type: 'PostgreSQL'
                            },
                            email: emailStatus
                        }
                    }
                });
            } catch (error) {
                res.status(500).json({
                    success: false,
                    error: 'Error obteniendo estado del servidor'
                });
            }
        });

    // Ruta catch-all para SPA del panel admin
    this.app.get(/.*/, (req, res) => {
            if (req.path.startsWith('/api/')) {
                return res.status(404).json({
                    success: false,
                    error: 'Endpoint no encontrado'
                });
            }
            
            // Servir index.html para rutas del frontend
            res.sendFile(join(__dirname, 'public', 'index.html'));
        });
    }

    /**
     * Configura servicio de archivos estáticos para el panel admin
     */
    setupStaticFiles() {
        // Servir archivos estáticos del panel de administración
        this.app.use(express.static(join(__dirname, 'public'), {
            maxAge: '1d',
            etag: true
        }));
    }

    /**
     * Configura manejo global de errores
     */
    setupErrorHandling() {
        // Manejo de errores 404
        this.app.use((req, res) => {
            if (req.path.startsWith('/api/')) {
                res.status(404).json({
                    success: false,
                    error: 'Endpoint no encontrado'
                });
            } else {
                res.status(404).sendFile(join(__dirname, 'public', '404.html'));
            }
        });

        // Manejo global de errores
        this.app.use((error, req, res, next) => {
            console.error('Error no manejado:', error);

            // No revelar detalles del error en producción
            const isDevelopment = process.env.NODE_ENV === 'development';

            res.status(500).json({
                success: false,
                error: 'Error interno del servidor',
                ...(isDevelopment && { details: error.message, stack: error.stack })
            });
        });

        // Manejo de promesas rechazadas
        process.on('unhandledRejection', (reason, promise) => {
            console.error('Promesa rechazada no manejada:', reason);
        });

        // Manejo de excepciones no capturadas
        process.on('uncaughtException', (error) => {
            console.error('Excepción no capturada:', error);
            this.gracefulShutdown();
        });

        // Manejo de señales de cierre
        process.on('SIGTERM', () => this.gracefulShutdown());
        process.on('SIGINT', () => this.gracefulShutdown());
    }

    /**
     * Inicia el servidor
     */
    async start() {
        try {
            await this.initialize();

            this.server = this.app.listen(this.port, () => {
                console.log('═'.repeat(60));
                console.log('🎊 SERVIDOR DE AUTENTICACIÓN INICIADO');
                console.log('═'.repeat(60));
                console.log(`🌐 URL: http://localhost:${this.port}`);
                console.log(`📊 Panel Admin: http://localhost:${this.port}/admin`);
                console.log(`🔌 API: http://localhost:${this.port}/api`);
                console.log(`🗄️ Base de Datos: PostgreSQL - ${this.db.getConnectionInfo().connected ? 'Conectada' : 'Desconectada'}`);
                console.log(`📧 Email: ${this.emailService.isConfigured() ? 'Configurado' : 'No configurado'}`);
                console.log(`🛡️ JWT: ${process.env.JWT_SECRET ? 'Configurado' : 'No configurado'}`);
                console.log('═'.repeat(60));
            });

            // Iniciar limpieza periódica de sesiones expiradas (cada 30 minutos)
            this.startSessionCleanupJob();

        } catch (error) {
            console.error('❌ Error iniciando servidor:', error.message);
            process.exit(1);
        }
    }

    /**
     * Inicia job de limpieza periódica de sesiones expiradas
     */
    startSessionCleanupJob() {
        const CLEANUP_INTERVAL = 30 * 60 * 1000; // 30 minutos

        this.cleanupInterval = setInterval(async () => {
            try {
                await this.db.cleanExpiredSessions();
            } catch (error) {
                console.error('❌ Error en limpieza de sesiones:', error.message);
            }
        }, CLEANUP_INTERVAL);

        console.log('🧹 Job de limpieza de sesiones iniciado (cada 30 min)');
    }

    /**
     * Cierre elegante del servidor
     */
    async gracefulShutdown() {
        console.log('\n🛑 Iniciando cierre elegante del servidor...');

        try {
            // Detener job de limpieza
            if (this.cleanupInterval) {
                clearInterval(this.cleanupInterval);
                console.log('✅ Job de limpieza detenido');
            }

            // Cerrar servidor HTTP
            if (this.server) {
                await new Promise((resolve) => {
                    this.server.close(resolve);
                });
                console.log('✅ Servidor HTTP cerrado');
            }

            // Cerrar conexión a base de datos
            if (this.db) {
                await this.db.close();
                console.log('✅ Base de datos cerrada');
            }

            console.log('✅ Cierre elegante completado');
            process.exit(0);

        } catch (error) {
            console.error('❌ Error en cierre elegante:', error.message);
            process.exit(1);
        }
    }
}

// Crear e iniciar servidor si este archivo se ejecuta directamente
if (import.meta.url === `file://${process.argv[1]}`) {
    const server = new AuthServer();
    server.start();
}

export default AuthServer;