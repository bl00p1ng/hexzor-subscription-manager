import express from 'express';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';

const router = express.Router();

/**
 * Rate limiting para diferentes endpoints
 */
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutos
    max: 5, // 5 intentos por IP
    message: { 
        error: 'Demasiados intentos de autenticación. Intenta de nuevo en 15 minutos.' 
    },
    standardHeaders: true,
    legacyHeaders: false
});

const codeRequestLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutos
    max: 3, // 3 solicitudes de código por IP
    message: { 
        error: 'Demasiadas solicitudes de código. Intenta de nuevo en 5 minutos.' 
    }
});

const codeVerifyLimiter = rateLimit({
    windowMs: 10 * 60 * 1000, // 10 minutos
    max: 10, // 10 intentos de verificación por IP
    message: { 
        error: 'Demasiados intentos de verificación. Intenta de nuevo en 10 minutos.' 
    }
});

/**
 * POST /api/auth/admin/login
 * Autenticación de administradores
 */
router.post('/admin/login', 
    authLimiter,
    [
        body('email')
            .isEmail()
            .normalizeEmail()
            .withMessage('Email válido requerido'),
        body('password')
            .isLength({ min: 6 })
            .withMessage('Contraseña debe tener al menos 6 caracteres')
    ],
    async (req, res) => {
        try {
            // Validar entrada
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    error: 'Datos inválidos',
                    details: errors.array()
                });
            }

            const { email, password } = req.body;
            const { db, emailService } = req.app.locals;

            // Verificar credenciales
            const admin = await db.verifyAdminUser(email, password);
            
            if (!admin) {
                // Log intento fallido
                await db.logAccess({
                    email,
                    action: 'admin_login_failed',
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    success: false,
                    errorMessage: 'Credenciales inválidas'
                });

                return res.status(401).json({
                    success: false,
                    error: 'Credenciales inválidas'
                });
            }

            // Generar JWT token
            const token = jwt.sign(
                { 
                    adminId: admin.id, 
                    email: admin.email,
                    role: 'admin'
                },
                process.env.JWT_SECRET,
                { expiresIn: '8h' }
            );

            // Log acceso exitoso
            await db.logAccess({
                email,
                action: 'admin_login_success',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                success: true
            });

            res.json({
                success: true,
                data: {
                    token,
                    admin: {
                        id: admin.id,
                        email: admin.email,
                        name: admin.name
                    }
                }
            });

        } catch (error) {
            console.error('Error en login admin:', error.message);
            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    }
);

/**
 * POST /api/auth/request-code
 * Solicita código de acceso para usuarios finales
 */
router.post('/request-code',
    codeRequestLimiter,
    [
        body('email')
            .isEmail()
            .normalizeEmail()
            .withMessage('Email válido requerido')
    ],
    async (req, res) => {
        try {
            // Validar entrada
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    error: 'Email inválido'
                });
            }

            const { email } = req.body;
            const { db, emailService } = req.app.locals;

            // Verificar suscripción activa
            const subscription = await db.checkActiveSubscription(email);
            
            if (!subscription) {
                // Log intento con suscripción inválida
                await db.logAccess({
                    email,
                    action: 'code_request_failed',
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    success: false,
                    errorMessage: 'Sin suscripción activa'
                });

                return res.status(403).json({
                    success: false,
                    error: 'No tienes una suscripción activa. Contacta al soporte.'
                });
            }

            // Generar código de acceso
            const code = await db.generateAccessCode(
                email,
                req.ip,
                req.get('User-Agent')
            );

            // Enviar código por email
            const emailSent = await emailService.sendAccessCode(
                email, 
                code, 
                subscription.customer_name
            );

            // Log solicitud exitosa
            await db.logAccess({
                email,
                action: 'code_request_success',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                success: true
            });

            res.json({
                success: true,
                message: emailSent ? 
                    'Código enviado a tu email. Válido por 10 minutos.' :
                    'Código generado. Revisa la consola del servidor.',
                data: {
                    emailSent,
                    expiresInMinutes: 10
                }
            });

        } catch (error) {
            console.error('Error solicitando código:', error.message);
            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    }
);

/**
 * POST /api/auth/verify-code
 * Verifica código de acceso y genera token de sesión
 */
router.post('/verify-code',
    codeVerifyLimiter,
    [
        body('email')
            .isEmail()
            .normalizeEmail()
            .withMessage('Email válido requerido'),
        body('code')
            .isLength({ min: 8, max: 8 })
            .isAlphanumeric()
            .withMessage('Código inválido')
    ],
    async (req, res) => {
        try {
            // Validar entrada
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    error: 'Datos inválidos'
                });
            }

            const { email, code } = req.body;
            const { db, emailService } = req.app.locals;

            // Verificar código
            const isValidCode = await db.verifyAccessCode(email, code.toUpperCase());
            
            if (!isValidCode) {
                // Log verificación fallida
                await db.logAccess({
                    email,
                    action: 'code_verify_failed',
                    ipAddress: req.ip,
                    userAgent: req.get('User-Agent'),
                    success: false,
                    errorMessage: 'Código inválido o expirado'
                });

                return res.status(401).json({
                    success: false,
                    error: 'Código inválido o expirado'
                });
            }

            // Obtener datos de suscripción
            const subscription = await db.checkActiveSubscription(email);
            
            if (!subscription) {
                return res.status(403).json({
                    success: false,
                    error: 'Suscripción expirada o inválida'
                });
            }

            // Generar token de sesión
            const token = jwt.sign(
                { 
                    email: email,
                    customerId: subscription.id,
                    customerName: subscription.customer_name,
                    subscriptionEnd: subscription.end_date,
                    role: 'user'
                },
                process.env.JWT_SECRET,
                { expiresIn: '24h' }
            );

            // Log acceso exitoso
            await db.logAccess({
                email,
                action: 'code_verify_success',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                success: true
            });

            // Notificar a admin (opcional)
            if (process.env.NOTIFY_ADMIN_ON_ACCESS === 'true') {
                await emailService.sendAdminNotification(email, req.ip);
            }

            res.json({
                success: true,
                message: 'Acceso autorizado',
                data: {
                    token,
                    user: {
                        email: email,
                        name: subscription.customer_name,
                        subscriptionEnd: subscription.end_date
                    }
                }
            });

        } catch (error) {
            console.error('Error verificando código:', error.message);
            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    }
);

/**
 * POST /api/auth/validate-token
 * Valida token de sesión (para la app principal)
 */
router.post('/validate-token',
    [
        body('token')
            .isString()
            .isLength({ min: 10 })
            .withMessage('Token requerido')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    error: 'Token requerido'
                });
            }

            const { token } = req.body;

            // Verificar token JWT
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            
            // Si es token de usuario, verificar suscripción activa
            if (decoded.role === 'user') {
                const { db } = req.app.locals;
                const subscription = await db.checkActiveSubscription(decoded.email);
                
                if (!subscription) {
                    return res.status(403).json({
                        success: false,
                        error: 'Suscripción expirada'
                    });
                }
            }

            res.json({
                success: true,
                data: {
                    valid: true,
                    user: {
                        email: decoded.email,
                        role: decoded.role,
                        name: decoded.customerName || decoded.name,
                        subscriptionEnd: decoded.subscriptionEnd
                    }
                }
            });

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

            console.error('Error validando token:', error.message);
            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    }
);

export default router;