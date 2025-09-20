import express from 'express';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { body, validationResult } from 'express-validator';
import { captureDeviceFingerprint } from '../middleware/deviceFingerprint.js';

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
    captureDeviceFingerprint,  // Nuevo middleware
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
            const deviceFingerprint = req.deviceFingerprint;
            const sessionToken = req.cookies.session_token || null;

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
                    errorMessage: 'Sin suscripción activa',
                    metadata: { deviceFingerprint }
                });

                return res.status(403).json({
                    success: false,
                    error: 'No tienes una suscripción activa. Contacta al soporte.'
                });
            }

            // Verificar elegibilidad para generar código
            let codeResult;
            try {
                codeResult = await db.generateAccessCodeWithSessionControl(
                    email,
                    deviceFingerprint,
                    sessionToken
                );
            } catch (error) {
                if (error.message.startsWith('MULTIPLE_SESSIONS_BLOCKED:')) {
                    const blockedUntil = error.message.split(':')[1];
                    
                    // Log bloqueo por sesiones múltiples
                    await db.logAccess({
                        email,
                        action: 'code_request_blocked',
                        ipAddress: req.ip,
                        userAgent: req.get('User-Agent'),
                        success: false,
                        errorMessage: 'Sesiones múltiples bloqueadas',
                        metadata: { deviceFingerprint, blockedUntil }
                    });

                    return res.status(429).json({
                        success: false,
                        error: 'Ya existe una sesión activa en otro dispositivo. Espera a que expire el código anterior o cierra la otra sesión.',
                        code: 'MULTIPLE_SESSIONS_BLOCKED',
                        blockedUntil: new Date(blockedUntil).toISOString(),
                        retryAfterMinutes: Math.ceil((new Date(blockedUntil) - new Date()) / (1000 * 60))
                    });
                }
                throw error; // Re-lanzar otros errores
            }

            // Si no hay código nuevo (reutilización), no enviar email
            let emailSent = false;
            if (!codeResult.isRenewal || codeResult.reason === 'new_code_generated') {
                emailSent = await emailService.sendAccessCode(
                    email, 
                    codeResult.code, 
                    subscription.customer_name
                );
            }

            // Configurar cookie de sesión si es nueva sesión
            if (codeResult.sessionToken && !sessionToken) {
                res.cookie('session_token', codeResult.sessionToken, {
                    httpOnly: true,
                    secure: process.env.NODE_ENV === 'production',
                    sameSite: 'strict',
                    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 días
                });
            }

            // Log solicitud exitosa
            await db.logAccess({
                email,
                action: 'code_request_success',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                success: true,
                metadata: {
                    deviceFingerprint,
                    reason: codeResult.reason,
                    isRenewal: codeResult.isRenewal,
                    emailSent
                }
            });

            // Respuesta personalizada según el tipo de solicitud
            let message;
            if (codeResult.isRenewal) {
                message = 'Código de acceso renovado. Válido por 10 minutos.';
            } else if (codeResult.reason === 'same_device') {
                message = 'Código reutilizado del mismo dispositivo. Válido por 10 minutos.';
            } else {
                message = emailSent ? 
                    'Código enviado a tu email. Válido por 10 minutos.' :
                    'Código generado. Revisa la consola del servidor.';
            }

            res.json({
                success: true,
                message,
                data: {
                    emailSent,
                    expiresInMinutes: 10,
                    isRenewal: codeResult.isRenewal,
                    reason: codeResult.reason
                }
            });

        } catch (error) {
            console.error('Error solicitando código:', error.message);
            
            // Log error genérico
            await req.app.locals.db.logAccess({
                email: req.body?.email || 'unknown',
                action: 'code_request_error',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                success: false,
                errorMessage: error.message,
                metadata: { deviceFingerprint: req.deviceFingerprint }
            }).catch(() => {}); // Ignorar errores de logging

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

            console.log(`🔑 Verificando código para ${email}: ${code}`);

            // Verificar código
            const isValidCode = await db.verifyAccessCode(email, code.toUpperCase());

            console.log(`🔍 Código válido: ${isValidCode}`);
            
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
 * Valida un token guardado y verifica el estado de la suscripción
 * Endpoint: POST /api/auth/validate-token
 */
router.post('/validate-token', [
    body('token').notEmpty().withMessage('Token es requerido'),
    body('email').isEmail().withMessage('Email válido es requerido')
], async (req, res) => {
    try {
        // Validar errores de entrada
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({
                success: false,
                error: 'Datos inválidos',
                details: errors.array()
            });
        }

        const { token, email } = req.body;

        // Verificar el token JWT
        let decoded;
        try {
            decoded = jwt.verify(token, process.env.JWT_SECRET);
        } catch (jwtError) {
            return res.status(401).json({
                success: false,
                error: 'Token inválido o expirado'
            });
        }

        // Verificar que el email del token coincida con el solicitado
        if (decoded.email !== email) {
            return res.status(401).json({
                success: false,
                error: 'Token no corresponde al email proporcionado'
            });
        }

        // Verificar que el token sea del tipo correcto (usuario, no admin)
        if (decoded.role !== 'user') {
            return res.status(401).json({
                success: false,
                error: 'Tipo de token inválido'
            });
        }

        // Verificar que la suscripción siga activa en la base de datos
        const { db } = req.app.locals;
        const subscription = await db.checkActiveSubscription(email);

        if (!subscription) {
            return res.status(401).json({
                success: false,
                error: 'Suscripción no activa o expirada'
            });
        }

        // Verificar que la fecha de expiración del token aún sea válida
        const now = new Date();
        const tokenExpiry = new Date(decoded.exp * 1000); // JWT exp está en segundos

        if (now > tokenExpiry) {
            return res.status(401).json({
                success: false,
                error: 'Token expirado'
            });
        }

        // Verificar que la suscripción no haya expirado
        const subscriptionEnd = new Date(subscription.subscription_end);
        if (now > subscriptionEnd) {
            return res.status(401).json({
                success: false,
                error: 'Suscripción expirada'
            });
        }

        // Token válido y suscripción activa
        console.log(`✅ Token validado exitosamente para: ${email}`);

        // Retornar información actualizada de la suscripción
        res.json({
            success: true,
            message: 'Token válido',
            subscription: {
                customerId: subscription.customer_id,
                customerName: subscription.customer_name,
                subscriptionEnd: subscription.subscription_end,
                subscriptionStatus: 'active'
            },
            tokenExpiry: tokenExpiry.toISOString()
        });

    } catch (error) {
        console.error('Error validando token:', error.message);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
});

export default router;