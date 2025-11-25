import express from 'express';
import { body, query, validationResult } from 'express-validator';
import { authenticateAdmin } from '../middleware/auth.js';

const router = express.Router();

// Aplicar middleware de autenticación a todas las rutas de admin
router.use(authenticateAdmin);

/**
 * GET /api/admin/subscriptions
 * Obtiene lista de suscripciones con paginación y filtros
 */
router.get('/subscriptions',
    [
        query('page')
            .optional()
            .isInt({ min: 1 })
            .withMessage('Página debe ser un número positivo'),
        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 })
            .withMessage('Límite debe estar entre 1 y 100'),
        query('status')
            .optional()
            .isIn(['active', 'suspended', 'expired'])
            .withMessage('Estado inválido')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    error: 'Parámetros inválidos',
                    details: errors.array()
                });
            }

            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 20;
            const status = req.query.status || null;

            const { db } = req.app.locals;
            const result = await db.getSubscriptions(page, limit, status);

            res.json({
                success: true,
                data: result
            });

        } catch (error) {
            console.error('Error obteniendo suscripciones:', error.message);
            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    }
);

/**
 * POST /api/admin/subscriptions
 * Crea una nueva suscripción
 */
router.post('/subscriptions',
    [
        body('email')
            .isEmail()
            .normalizeEmail()
            .withMessage('Email válido requerido'),
        body('customerName')
            .isLength({ min: 2, max: 100 })
            .trim()
            .withMessage('Nombre debe tener entre 2 y 100 caracteres'),
        body('startDate')
            .isISO8601()
            .withMessage('Fecha de inicio inválida'),
        body('endDate')
            .isISO8601()
            .withMessage('Fecha de fin inválida'),
        body('subscriptionId')
            .optional()
            .isString()
            .trim(),
        body('hotmartTransactionId')
            .optional()
            .isString()
            .trim(),
        body('notes')
            .optional()
            .isLength({ max: 500 })
            .trim()
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    error: 'Datos inválidos',
                    details: errors.array()
                });
            }

            const {
                email,
                customerName,
                startDate,
                endDate,
                subscriptionId,
                hotmartTransactionId,
                notes
            } = req.body;

            // Validar que fecha de fin sea posterior a fecha de inicio
            if (new Date(endDate) <= new Date(startDate)) {
                return res.status(400).json({
                    success: false,
                    error: 'La fecha de fin debe ser posterior a la fecha de inicio'
                });
            }

            const { db } = req.app.locals;
            const adminId = req.admin.id;

            // Verificar si ya existe suscripción activa para este email
            const existingSubscription = await db.checkActiveSubscription(email);
            if (existingSubscription) {
                return res.status(409).json({
                    success: false,
                    error: 'Ya existe una suscripción activa para este email'
                });
            }

            // Crear nueva suscripción
            const subscriptionData = {
                email,
                customerName,
                startDate,
                endDate,
                subscriptionId,
                hotmartTransactionId,
                notes
            };

            const newSubscriptionId = await db.addActiveSubscription(subscriptionData, adminId);

            // Log de la acción
            await db.logAccess({
                email: req.admin.email,
                action: 'subscription_created',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                success: true,
                errorMessage: `Created subscription for ${email}`
            });

            res.status(201).json({
                success: true,
                message: 'Suscripción creada exitosamente',
                data: {
                    id: newSubscriptionId,
                    email,
                    customerName,
                    startDate,
                    endDate
                }
            });

        } catch (error) {
            console.error('Error creando suscripción:', error.message);
            
            if (error.code === 'SQLITE_CONSTRAINT_UNIQUE') {
                return res.status(409).json({
                    success: false,
                    error: 'Ya existe una suscripción para este email'
                });
            }

            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    }
);

/**
 * PUT /api/admin/subscriptions/:id
 * Actualiza una suscripción existente
 */
router.put('/subscriptions/:id',
    [
        body('customerName')
            .optional()
            .isLength({ min: 2, max: 100 })
            .trim(),
        body('endDate')
            .optional()
            .isISO8601(),
        body('status')
            .optional()
            .isIn(['active', 'suspended', 'expired']),
        body('notes')
            .optional()
            .isLength({ max: 500 })
            .trim()
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    error: 'Datos inválidos',
                    details: errors.array()
                });
            }

            const subscriptionId = req.params.id;
            const updates = req.body;
            const { db } = req.app.locals;

            // Usar el método updateSubscription del PostgreSQLManager
            const updated = await db.updateSubscription(subscriptionId, updates);

            if (!updated) {
                return res.status(404).json({
                    success: false,
                    error: 'Suscripción no encontrada o sin cambios'
                });
            }

            // Log de la acción
            await db.logAccess({
                email: req.admin.email,
                action: 'subscription_updated',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                success: true,
                errorMessage: `Updated subscription ID ${subscriptionId}`
            });

            res.json({
                success: true,
                message: 'Suscripción actualizada exitosamente'
            });

        } catch (error) {
            console.error('Error actualizando suscripción:', error.message);
            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    }
);

/**
 * POST /api/admin/subscriptions/:id/renew
 * Renueva una suscripción por N meses
 */
router.post('/subscriptions/:id/renew',
    [
        body('months')
            .isInt({ min: 1, max: 24 })
            .withMessage('Meses debe ser un número entre 1 y 24')
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    error: 'Datos inválidos',
                    details: errors.array()
                });
            }

            const subscriptionId = req.params.id;
            const { months } = req.body;
            const { db } = req.app.locals;

            // Obtener suscripción actual
            const result = await db.query(
                'SELECT * FROM active_subscriptions WHERE id = $1',
                [subscriptionId]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    success: false,
                    error: 'Suscripción no encontrada'
                });
            }

            const subscription = result.rows[0];

            // Calcular nueva fecha de fin
            const currentEndDate = new Date(subscription.end_date);
            const newEndDate = new Date(currentEndDate);
            newEndDate.setMonth(newEndDate.getMonth() + months);

            // Actualizar suscripción
            const updated = await db.updateSubscription(subscriptionId, {
                endDate: newEndDate.toISOString().split('T')[0],
                status: 'active'
            });

            if (!updated) {
                return res.status(500).json({
                    success: false,
                    error: 'No se pudo actualizar la suscripción'
                });
            }

            // Log de la acción
            await db.logAccess({
                email: req.admin.email,
                action: 'subscription_renewed',
                ipAddress: req.ip,
                userAgent: req.get('User-Agent'),
                success: true,
                errorMessage: `Renewed subscription ${subscription.email} for ${months} month(s). New end date: ${newEndDate.toISOString().split('T')[0]}`
            });

            res.json({
                success: true,
                message: `Suscripción renovada por ${months} ${months === 1 ? 'mes' : 'meses'}`,
                data: {
                    email: subscription.email,
                    previousEndDate: subscription.end_date,
                    newEndDate: newEndDate.toISOString().split('T')[0]
                }
            });

        } catch (error) {
            console.error('Error renovando suscripción:', error.message);
            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    }
);

/**
 * DELETE /api/admin/subscriptions/:id
 * Elimina una suscripción (cambiar estado a expirada)
 */
router.delete('/subscriptions/:id', async (req, res) => {
    try {
        const subscriptionId = req.params.id;
        const { db } = req.app.locals;

        // Cambiar estado a expirada en lugar de eliminar
        const result = await db.query(
            'UPDATE active_subscriptions SET status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            ['expired', subscriptionId]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({
                success: false,
                error: 'Suscripción no encontrada'
            });
        }

        // Log de la acción
        await db.logAccess({
            email: req.admin.email,
            action: 'subscription_expired',
            ipAddress: req.ip,
            userAgent: req.get('User-Agent'),
            success: true,
            errorMessage: `Expired subscription ID ${subscriptionId}`
        });

        res.json({
            success: true,
            message: 'Suscripción expirada exitosamente'
        });

    } catch (error) {
        console.error('Error expirando suscripción:', error.message);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
});

/**
 * GET /api/admin/logs
 * Obtiene logs de acceso con paginación
 */
router.get('/logs',
    [
        query('page')
            .optional()
            .isInt({ min: 1 }),
        query('limit')
            .optional()
            .isInt({ min: 1, max: 100 }),
        query('email')
            .optional()
            .isEmail()
            .normalizeEmail(),
        query('action')
            .optional()
            .isString()
    ],
    async (req, res) => {
        try {
            const errors = validationResult(req);
            if (!errors.isEmpty()) {
                return res.status(400).json({
                    success: false,
                    error: 'Parámetros inválidos',
                    details: errors.array()
                });
            }

            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 50;
            const email = req.query.email;
            const action = req.query.action;
            const offset = (page - 1) * limit;

            const { db } = req.app.locals;

            // Construir query con filtros
            let whereClause = '';
            let params = [];

            const conditions = [];
            if (email) {
                conditions.push('email = ?');
                params.push(email);
            }
            if (action) {
                conditions.push('action = ?');
                params.push(action);
            }

            if (conditions.length > 0) {
                whereClause = 'WHERE ' + conditions.join(' AND ');
            }

            // Obtener logs
            const logs = await db.getMany(
                `SELECT * FROM access_logs ${whereClause} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
                [...params, limit, offset]
            );

            // Contar total
            const countResult = await db.getOne(
                `SELECT COUNT(*) as total FROM access_logs ${whereClause}`,
                params
            );

            res.json({
                success: true,
                data: {
                    logs,
                    pagination: {
                        page,
                        limit,
                        total: countResult.total,
                        totalPages: Math.ceil(countResult.total / limit)
                    }
                }
            });

        } catch (error) {
            console.error('Error obteniendo logs:', error.message);
            res.status(500).json({
                success: false,
                error: 'Error interno del servidor'
            });
        }
    }
);

/**
 * GET /api/admin/stats
 * Obtiene estadísticas generales del sistema
 */
router.get('/stats', async (req, res) => {
    try {
        const { db } = req.app.locals;

        // Usar el método de estadísticas del PostgreSQLManager
        const stats = await db.getSystemStats();

        res.json({
            success: true,
            data: stats
        });

    } catch (error) {
        console.error('Error obteniendo estadísticas:', error.message);
        res.status(500).json({
            success: false,
            error: 'Error interno del servidor'
        });
    }
});

export default router;