import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { validationResult } from 'express-validator';

/**
 * Middleware para autenticar administradores
 * Verifica token JWT en header Authorization
 */
export const authenticateAdmin = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'Token de autorización requerido'
            });
        }

        const token = authHeader.substring(7); // Remover 'Bearer '

        // Verificar token JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Verificar que es un token de administrador
        if (decoded.role !== 'admin') {
            return res.status(403).json({
                success: false,
                error: 'Acceso denegado. Se requieren permisos de administrador.'
            });
        }

        // Agregar datos del admin al request
        req.admin = {
            id: decoded.adminId,
            email: decoded.email,
            role: decoded.role
        };

        next();

    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                error: 'Token expirado'
            });
        }
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                error: 'Token inválido'
            });
        }

        console.error('Error en middleware de autenticación admin:', error.message);
        return res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
};

/**
 * Middleware para autenticar usuarios finales
 * Verifica token JWT, suscripción activa Y sesión única por dispositivo
 */
export const authenticateUser = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            return res.status(401).json({
                success: false,
                error: 'Token de autorización requerido'
            });
        }

        const token = authHeader.substring(7);

        // Verificar token JWT
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Verificar que es un token de usuario
        if (decoded.role !== 'user') {
            return res.status(403).json({
                success: false,
                error: 'Token de usuario inválido'
            });
        }

        // Verificar suscripción activa en base de datos
        const { db } = req.app.locals;
        const subscription = await db.checkActiveSubscription(decoded.email);

        if (!subscription) {
            return res.status(403).json({
                success: false,
                error: 'Suscripción expirada o inválida'
            });
        }

        // VALIDACIÓN DE SESIÓN ÚNICA POR DISPOSITIVO
        const deviceFingerprint = req.headers['x-device-fingerprint'];

        if (!deviceFingerprint) {
            return res.status(400).json({
                success: false,
                error: 'Device fingerprint requerido'
            });
        }

        // Hash del token para comparación
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

        // Validar que solo exista una sesión activa
        const sessionValidation = await db.validateSingleSession(
            decoded.email,
            deviceFingerprint,
            tokenHash
        );

        if (!sessionValidation.valid) {
            // Log de intento de acceso multi-dispositivo
            await db.logAccess({
                email: decoded.email,
                action: 'BLOCKED_MULTIPLE_DEVICE_ATTEMPT',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                success: false,
                errorMessage: `Sesión activa en otro dispositivo. Bloqueado hasta: ${sessionValidation.blockedUntil}`
            });

            return res.status(403).json({
                success: false,
                error: 'Ya existe una sesión activa en otro dispositivo',
                code: 'MULTIPLE_DEVICE_BLOCKED',
                blockedUntil: sessionValidation.blockedUntil,
                message: 'Solo puedes usar tu cuenta en un dispositivo a la vez. Espera a que expire la sesión del otro dispositivo o contáctanos para adquirir licencias adicionales.'
            });
        }

        // Agregar datos del usuario al request
        req.user = {
            email: decoded.email,
            customerId: decoded.customerId,
            customerName: decoded.customerName,
            subscriptionEnd: decoded.subscriptionEnd,
            role: decoded.role,
            subscription: subscription,
            deviceFingerprint: deviceFingerprint,
            sessionValidation: sessionValidation
        };

        next();

    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({
                success: false,
                error: 'Sesión expirada. Solicita un nuevo código de acceso.'
            });
        }

        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({
                success: false,
                error: 'Token inválido'
            });
        }

        console.error('Error en middleware de usuario:', error.message);
        return res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
};

/**
 * Middleware de validación opcional de usuario
 * No falla si no hay token, pero valida si está presente
 */
export const optionalUserAuth = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader || !authHeader.startsWith('Bearer ')) {
            // No hay token, continuar sin autenticación
            req.user = null;
            return next();
        }

        const token = authHeader.substring(7);
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        if (decoded.role === 'user') {
            const { db } = req.app.locals;
            const subscription = await db.checkActiveSubscription(decoded.email);
            
            if (subscription) {
                req.user = {
                    email: decoded.email,
                    customerId: decoded.customerId,
                    customerName: decoded.customerName,
                    subscriptionEnd: decoded.subscriptionEnd,
                    role: decoded.role,
                    subscription: subscription
                };
            }
        }

        next();

    } catch (error) {
        // En caso de error, continuar sin autenticación
        req.user = null;
        next();
    }
};

/**
 * Middleware para validar que el request viene de una IP permitida
 * Útil para endpoints sensibles de administración
 */
export const validateAllowedIP = (allowedIPs = []) => {
    return (req, res, next) => {
        if (allowedIPs.length === 0) {
            // Si no hay IPs configuradas, permitir todas
            return next();
        }

        const clientIP = req.ip || req.connection.remoteAddress;
        
        if (!allowedIPs.includes(clientIP)) {
            console.warn(`⚠️ Intento de acceso desde IP no autorizada: ${clientIP}`);
            return res.status(403).json({
                success: false,
                error: 'Acceso denegado desde esta IP'
            });
        }

        next();
    };
};

/**
 * Middleware para logging de requests de administración
 */
export const logAdminRequests = async (req, res, next) => {
    try {
        const { db } = req.app.locals;
        const startTime = Date.now();

        // Log del request
        const logData = {
            email: req.admin?.email || 'unknown',
            action: `${req.method} ${req.path}`,
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            success: true // Se actualizará si hay error
        };

        // Continuar con el request
        res.on('finish', async () => {
            try {
                const duration = Date.now() - startTime;
                logData.success = res.statusCode < 400;
                
                if (!logData.success) {
                    logData.errorMessage = `HTTP ${res.statusCode}`;
                }

                await db.logAccess(logData);
            } catch (error) {
                console.error('Error logging admin request:', error.message);
            }
        });

        next();

    } catch (error) {
        console.error('Error en middleware de logging:', error.message);
        next(); // Continuar aunque falle el logging
    }
};

/**
 * Middleware para limitar acceso basado en horarios
 * Útil para restricciones de seguridad adicionales
 */
export const restrictBySchedule = (allowedHours = { start: 0, end: 24 }) => {
    return (req, res, next) => {
        const now = new Date();
        const currentHour = now.getHours();
        
        if (currentHour < allowedHours.start || currentHour >= allowedHours.end) {
            return res.status(403).json({
                success: false,
                error: `Acceso permitido solo entre ${allowedHours.start}:00 y ${allowedHours.end}:00`
            });
        }

        next();
    };
};

/**
 * Middleware para validar formato de UUIDs en parámetros
 * Útil para endpoints que reciben IDs de PostgreSQL
 */
export const validateUUID = (paramName = 'id') => {
    return (req, res, next) => {
        const uuid = req.params[paramName];
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        
        if (!uuid || !uuidRegex.test(uuid)) {
            return res.status(400).json({
                success: false,
                error: `Parámetro ${paramName} debe ser un UUID válido`
            });
        }

        next();
    };
};

/**
 * Middleware para manejar errores de validación de express-validator
 */
export const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    
    if (!errors.isEmpty()) {
        return res.status(400).json({
            success: false,
            error: 'Datos de entrada inválidos',
            details: errors.array().map(error => ({
                field: error.path || error.param,
                message: error.msg,
                value: error.value
            }))
        });
    }
    
    next();
};

/**
 * Middleware para sanitizar entradas de usuario
 * Remueve caracteres potencialmente peligrosos
 */
export const sanitizeInput = (req, res, next) => {
    const sanitize = (obj) => {
        for (const key in obj) {
            if (typeof obj[key] === 'string') {
                // Remover caracteres potencialmente peligrosos
                obj[key] = obj[key]
                    .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remover scripts
                    .replace(/javascript:/gi, '') // Remover javascript:
                    .replace(/on\w+\s*=/gi, '') // Remover event handlers
                    .trim();
            } else if (typeof obj[key] === 'object' && obj[key] !== null) {
                sanitize(obj[key]);
            }
        }
    };

    if (req.body) sanitize(req.body);
    if (req.query) sanitize(req.query);
    if (req.params) sanitize(req.params);

    next();
};

/**
 * Middleware para agregar headers de seguridad adicionales
 */
export const additionalSecurityHeaders = (req, res, next) => {
    // Prevenir clickjacking
    res.setHeader('X-Frame-Options', 'DENY');
    
    // Prevenir MIME type sniffing
    res.setHeader('X-Content-Type-Options', 'nosniff');
    
    // XSS Protection
    res.setHeader('X-XSS-Protection', '1; mode=block');
    
    // Referrer Policy
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    
    // Feature Policy
    res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
    
    next();
};

/**
 * Middleware para logging detallado de requests sospechosos
 */
export const logSuspiciousActivity = (req, res, next) => {
    const suspiciousPatterns = [
        /\.\.\//, // Path traversal
        /<script/i, // XSS attempts
        /union\s+select/i, // SQL injection
        /exec\s*\(/i, // Command injection
        /eval\s*\(/i // Code injection
    ];

    const checkSuspicious = (value) => {
        if (typeof value === 'string') {
            return suspiciousPatterns.some(pattern => pattern.test(value));
        }
        return false;
    };

    let suspicious = false;
    const suspiciousData = [];

    // Verificar body, query y params
    [req.body, req.query, req.params].forEach((obj, index) => {
        const source = ['body', 'query', 'params'][index];
        if (obj) {
            Object.entries(obj).forEach(([key, value]) => {
                if (checkSuspicious(value)) {
                    suspicious = true;
                    suspiciousData.push({ source, key, value });
                }
            });
        }
    });

    if (suspicious) {
        console.warn('🚨 ACTIVIDAD SOSPECHOSA DETECTADA:');
        console.warn(`   IP: ${req.ip}`);
        console.warn(`   User-Agent: ${req.get('User-Agent')}`);
        console.warn(`   URL: ${req.method} ${req.originalUrl}`);
        console.warn(`   Datos sospechosos:`, suspiciousData);

        // Log en base de datos si está disponible
        if (req.app.locals.db) {
            req.app.locals.db.logAccess({
                email: 'suspicious_activity',
                action: `SUSPICIOUS_${req.method}_${req.path}`,
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                success: false,
                errorMessage: JSON.stringify(suspiciousData)
            }).catch(error => {
                console.error('Error logging suspicious activity:', error);
            });
        }
    }

    next();
};

/**
 * Middleware para limitar tamaño de payload
 */
export const limitPayloadSize = (maxSize = '10mb') => {
    return (req, res, next) => {
        const contentLength = req.get('content-length');
        
        if (contentLength) {
            const sizeInBytes = parseInt(contentLength);
            const maxSizeInBytes = typeof maxSize === 'string' ? 
                parseFloat(maxSize) * (maxSize.includes('mb') ? 1024 * 1024 : 1024) :
                maxSize;

            if (sizeInBytes > maxSizeInBytes) {
                return res.status(413).json({
                    success: false,
                    error: 'Payload demasiado grande'
                });
            }
        }

        next();
    };
};

/**
 * Middleware combinado para aplicar múltiples validaciones de seguridad
 */
export const securityMiddleware = [
    additionalSecurityHeaders,
    sanitizeInput,
    logSuspiciousActivity,
    limitPayloadSize()
];

/**
 * Middleware para manejo de errores específicos de autenticación
 */
export const authErrorHandler = (error, req, res, next) => {
    console.error('Error en autenticación:', error);

    // Errores específicos de JWT
    if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
            success: false,
            error: 'Token inválido'
        });
    }

    if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
            success: false,
            error: 'Token expirado'
        });
    }

    // Error de base de datos de conexión PostgreSQL
    if (error.code === 'ECONNREFUSED' || error.code === 'ENOTFOUND') {
        return res.status(503).json({
            success: false,
            error: 'Servicio de base de datos temporalmente no disponible'
        });
    }

    // Errores específicos de PostgreSQL
    if (error.code === '23505') { // Duplicate key
        return res.status(409).json({
            success: false,
            error: 'El registro ya existe'
        });
    }

    if (error.code === '23503') { // Foreign key violation
        return res.status(400).json({
            success: false,
            error: 'Referencia inválida en los datos'
        });
    }

    if (error.code === '23502') { // Not null violation
        return res.status(400).json({
            success: false,
            error: 'Faltan campos obligatorios'
        });
    }

    // Error genérico
    res.status(500).json({
        success: false,
        error: 'Error interno del servidor'
    });
};