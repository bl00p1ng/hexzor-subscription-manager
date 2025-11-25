import pg from 'pg';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';
import { createLogger } from '../services/Logger.js';

const { Pool } = pg;
const logger = createLogger('DATABASE');

/**
 * Gestor de base de datos PostgreSQL para el sistema de autenticación
 * Maneja usuarios administradores, suscripciones activas y códigos de acceso
 */
class PostgreSQLManager {
    constructor() {
        this.pool = null;
        this.config = {
            host: process.env.DB_HOST || 'localhost',
            port: parseInt(process.env.DB_PORT) || 5432,
            database: process.env.DB_NAME || 'hexzor_subscriptions',
            user: process.env.DB_USER || 'hexzor_user',
            password: process.env.DB_PASSWORD || 'hexzor_password',
            // Configuración de pool para mejor rendimiento
            max: 25,                    // Máximo 20 conexiones
            min: 5,                     // Mínimo 5 conexiones
            idleTimeoutMillis: 30000,   // 30 segundos timeout
            connectionTimeoutMillis: 5000, // 5 segundos para conectar
            ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
        };
    }

    /**
     * Inicializa la conexión al pool de PostgreSQL
     * @returns {Promise<void>}
     */
    async initialize() {
        try {
            // Crear pool de conexiones
            this.pool = new Pool(this.config);

            // Probar conexión
            const client = await this.pool.connect();
            logger.info('Conexión a PostgreSQL establecida', {
                host: this.config.host,
                port: this.config.port,
                database: this.config.database
            });

            // Verificar versión
            const versionResult = await client.query('SELECT version()');
            const version = versionResult.rows[0].version.split(' ')[1];
            logger.info(`PostgreSQL versión: ${version}`, { version });

            client.release();

            // Crear tablas si no existen
            await this.createTables();

            logger.info('Base de datos PostgreSQL inicializada correctamente');
        } catch (error) {
            logger.error('Error conectando a PostgreSQL', error);
            logger.warn('💡 Sugerencias:');
            logger.warn('   1. Verificar que PostgreSQL esté ejecutándose');
            logger.warn('   2. Revisar credenciales en .env');
            logger.warn('   3. Verificar que la base de datos exista');
            throw error;
        }
    }

    /**
     * Crea las tablas necesarias para el sistema de autenticación
     * @returns {Promise<void>}
     */
    async createTables() {
        const client = await this.pool.connect();
        
        try {
            await client.query('BEGIN');

            // Habilitar extensión para UUIDs
            await client.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"');

            // Tabla de administradores
            await client.query(`
                CREATE TABLE IF NOT EXISTS admin_users (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    name VARCHAR(100) NOT NULL,
                    is_active BOOLEAN DEFAULT true,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    last_login TIMESTAMP WITH TIME ZONE NULL,
                    metadata JSONB DEFAULT '{}'::jsonb
                )
            `);

            // Tabla de suscripciones activas
            await client.query(`
                CREATE TABLE IF NOT EXISTS active_subscriptions (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    email VARCHAR(255) UNIQUE NOT NULL,
                    customer_name VARCHAR(100) NOT NULL,
                    subscription_id VARCHAR(100) NULL,
                    start_date DATE NOT NULL,
                    end_date DATE NOT NULL,
                    status VARCHAR(20) DEFAULT 'active' CHECK(status IN ('active', 'suspended', 'expired')),
                    hotmart_transaction_id VARCHAR(100) NULL,
                    notes TEXT NULL,
                    metadata JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    created_by UUID REFERENCES admin_users(id)
                )
            `);

            // Tabla de códigos de acceso temporales
            await client.query(`
                CREATE TABLE IF NOT EXISTS access_codes (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    email VARCHAR(255) NOT NULL,
                    code VARCHAR(20) NOT NULL,
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    used_at TIMESTAMP WITH TIME ZONE NULL,
                    ip_address INET NULL,
                    user_agent TEXT NULL,
                    metadata JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            `);

            // Tabla de logs de acceso
            await client.query(`
                CREATE TABLE IF NOT EXISTS access_logs (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    email VARCHAR(255) NOT NULL,
                    action VARCHAR(100) NOT NULL,
                    ip_address INET NULL,
                    user_agent TEXT NULL,
                    success BOOLEAN NOT NULL,
                    error_message TEXT NULL,
                    metadata JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
                )
            `);

            // Tabla de sesiones activas - Control de dispositivos únicos
            await client.query(`
                CREATE TABLE IF NOT EXISTS active_sessions (
                    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                    email VARCHAR(255) NOT NULL,
                    device_fingerprint TEXT NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    jwt_token_hash TEXT NOT NULL,
                    ip_address INET NULL,
                    user_agent TEXT NULL,
                    device_info JSONB DEFAULT '{}'::jsonb,
                    last_activity TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
                    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
                    UNIQUE(email, device_fingerprint)
                )
            `);

            // Crear índices para optimización
            const indexes = [
                'CREATE INDEX IF NOT EXISTS idx_subscriptions_email ON active_subscriptions(email)',
                'CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON active_subscriptions(status)',
                'CREATE INDEX IF NOT EXISTS idx_subscriptions_end_date ON active_subscriptions(end_date)',
                'CREATE INDEX IF NOT EXISTS idx_subscriptions_status_end_date ON active_subscriptions(status, end_date)',
                'CREATE INDEX IF NOT EXISTS idx_access_codes_email ON access_codes(email)',
                'CREATE INDEX IF NOT EXISTS idx_access_codes_expires ON access_codes(expires_at)',
                'CREATE INDEX IF NOT EXISTS idx_access_codes_email_expires ON access_codes(email, expires_at)',
                'CREATE INDEX IF NOT EXISTS idx_access_logs_email ON access_logs(email)',
                'CREATE INDEX IF NOT EXISTS idx_access_logs_created ON access_logs(created_at)',
                'CREATE INDEX IF NOT EXISTS idx_access_logs_action ON access_logs(action)',
                'CREATE INDEX IF NOT EXISTS idx_admin_users_email ON admin_users(email)',
                'CREATE INDEX IF NOT EXISTS idx_admin_users_active ON admin_users(is_active)',
                'CREATE INDEX IF NOT EXISTS idx_active_sessions_email ON active_sessions(email)',
                'CREATE INDEX IF NOT EXISTS idx_active_sessions_token ON active_sessions(session_token)',
                'CREATE INDEX IF NOT EXISTS idx_active_sessions_expires ON active_sessions(expires_at)',
                'CREATE INDEX IF NOT EXISTS idx_active_sessions_email_expires ON active_sessions(email, expires_at)'
            ];

            for (const index of indexes) {
                await client.query(index);
            }

            // Trigger para actualizar updated_at automáticamente
            await client.query(`
                CREATE OR REPLACE FUNCTION update_updated_at_column()
                RETURNS TRIGGER AS $$
                BEGIN
                    NEW.updated_at = NOW();
                    RETURN NEW;
                END;
                $$ language 'plpgsql'
            `);

            await client.query(`
                DROP TRIGGER IF EXISTS update_subscriptions_updated_at ON active_subscriptions
            `);

            await client.query(`
                CREATE TRIGGER update_subscriptions_updated_at
                    BEFORE UPDATE ON active_subscriptions
                    FOR EACH ROW
                    EXECUTE FUNCTION update_updated_at_column()
            `);

            await client.query('COMMIT');
            logger.info('Tablas e índices creados correctamente');

            await client.query(`
                ALTER TABLE access_codes
                ADD COLUMN IF NOT EXISTS device_fingerprint TEXT,
                ADD COLUMN IF NOT EXISTS session_token TEXT,
                ADD COLUMN IF NOT EXISTS is_renewal BOOLEAN DEFAULT FALSE,
                ADD COLUMN IF NOT EXISTS previous_session_id TEXT
            `);

            await client.query(`
                CREATE INDEX IF NOT EXISTS idx_access_codes_email_active
                ON access_codes(email)
                WHERE used_at IS NULL
            `);

            logger.info('Auto-migración: Control de sesiones aplicada');
        } catch (error) {
            await client.query('ROLLBACK');
            logger.error('Error creando tablas', error);
            throw error;
        } finally {
            client.release();
        }
    }

    /**
     * Ejecuta una query SQL
     * @param {string} text - Query SQL
     * @param {Array} params - Parámetros de la query
     * @returns {Promise<Object>} Resultado de la query
     */
    async query(text, params = []) {
        try {
            const result = await this.pool.query(text, params);
            logger.debug('Query ejecutada exitosamente', {
                query: text.substring(0, 100),
                rowCount: result.rowCount
            });
            return result;
        } catch (error) {
            logger.error('Error en query PostgreSQL', {
                error: error.message,
                code: error.code,
                query: text.substring(0, 200),
                params: JSON.stringify(params).substring(0, 100)
            });
            throw error;
        }
    }

    /**
     * Obtiene un registro de la base de datos
     * @param {string} text - Query SQL
     * @param {Array} params - Parámetros
     * @returns {Promise<Object|null>} Registro encontrado
     */
    async getOne(text, params = []) {
        const result = await this.query(text, params);
        return result.rows[0] || null;
    }

    /**
     * Obtiene múltiples registros de la base de datos
     * @param {string} text - Query SQL
     * @param {Array} params - Parámetros
     * @returns {Promise<Array>} Registros encontrados
     */
    async getMany(text, params = []) {
        const result = await this.query(text, params);
        return result.rows;
    }

    /**
     * Crea un usuario administrador
     * @param {Object} adminData - Datos del administrador
     * @returns {Promise<string>} ID del administrador creado
     */
    async createAdminUser(adminData) {
        const { email, password, name } = adminData;
        
        // Hash de la contraseña
        const passwordHash = await bcrypt.hash(password, 12);
        
        const result = await this.query(
            'INSERT INTO admin_users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id',
            [email, passwordHash, name]
        );
        
        return result.rows[0].id;
    }

    /**
     * Verifica las credenciales de un administrador
     * @param {string} email - Email del administrador
     * @param {string} password - Contraseña del administrador
     * @returns {Promise<Object|null>} Datos del administrador si es válido
     */
    async verifyAdminUser(email, password) {
        const admin = await this.getOne(
            'SELECT * FROM admin_users WHERE email = $1 AND is_active = true',
            [email]
        );
        
        if (!admin) {
            return null;
        }
        
        const isValid = await bcrypt.compare(password, admin.password_hash);
        
        if (isValid) {
            // Actualizar último login
            await this.query(
                'UPDATE admin_users SET last_login = NOW() WHERE id = $1',
                [admin.id]
            );
            
            // Eliminar hash de la respuesta
            delete admin.password_hash;
            return admin;
        }
        
        return null;
    }

    /**
     * Agrega una nueva suscripción activa
     * @param {Object} subscriptionData - Datos de la suscripción
     * @param {string} adminId - ID del administrador que la crea
     * @returns {Promise<string>} ID de la suscripción creada
     */
    async addActiveSubscription(subscriptionData, adminId) {
        const {
            email,
            customerName,
            subscriptionId,
            startDate,
            endDate,
            hotmartTransactionId,
            notes
        } = subscriptionData;

        const result = await this.query(
            `INSERT INTO active_subscriptions 
             (email, customer_name, subscription_id, start_date, end_date, 
              hotmart_transaction_id, notes, created_by) 
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
            [email, customerName, subscriptionId, startDate, endDate, 
             hotmartTransactionId, notes, adminId]
        );

        return result.rows[0].id;
    }

    /**
     * Verifica si un email tiene suscripción activa
     * @param {string} email - Email a verificar
     * @returns {Promise<Object|null>} Datos de la suscripción si está activa
     */
    async checkActiveSubscription(email) {
        const subscription = await this.getOne(
            `SELECT * FROM active_subscriptions 
             WHERE email = $1 AND status = 'active' AND end_date > CURRENT_DATE`,
            [email]
        );

        return subscription;
    }

    /**
     * Obtiene todas las suscripciones con paginación
     * @param {number} page - Página actual
     * @param {number} limit - Registros por página
     * @param {string} status - Filtro por estado
     * @returns {Promise<Object>} Suscripciones y metadatos
     */
    async getSubscriptions(page = 1, limit = 20, status = null) {
        const offset = (page - 1) * limit;
        
        let whereClause = '';
        let params = [];
        let paramIndex = 1;
        
        if (status) {
            whereClause = 'WHERE s.status = $' + paramIndex;
            params.push(status);
            paramIndex++;
        }

        // Agregar límite y offset a los parámetros
        params.push(limit, offset);

        const subscriptions = await this.getMany(
            `SELECT s.*, a.name as created_by_name 
             FROM active_subscriptions s 
             LEFT JOIN admin_users a ON s.created_by = a.id 
             ${whereClause}
             ORDER BY s.created_at DESC 
             LIMIT $${paramIndex} OFFSET $${paramIndex + 1}`,
            params
        );

        // Contar total
        const countParams = status ? [status] : [];
        const countResult = await this.getOne(
            `SELECT COUNT(*) as total FROM active_subscriptions ${whereClause}`,
            countParams
        );

        return {
            subscriptions,
            pagination: {
                page,
                limit,
                total: parseInt(countResult.total),
                totalPages: Math.ceil(countResult.total / limit)
            }
        };
    }

    /**
     * Genera y almacena un código de acceso temporal
     * @param {string} email - Email del usuario
     * @param {string} ipAddress - IP del usuario
     * @param {string} userAgent - User agent del usuario
     * @returns {Promise<string>} Código generado
     */
    async generateAccessCode(email, ipAddress, userAgent) {
        // Generar código alfanumérico de 8 caracteres
        const code = this.generateRandomCode(8);
        
        // Expiración en 10 minutos
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

        await this.query(
            'INSERT INTO access_codes (email, code, expires_at, ip_address, user_agent) VALUES ($1, $2, $3, $4, $5)',
            [email, code, expiresAt, ipAddress, userAgent]
        );

        return code;
    }

    /**
     * Verifica si el usuario puede generar un nuevo código de acceso
     * @param {string} email - Email del usuario
     * @param {string} deviceFingerprint - Fingerprint del dispositivo
     * @param {string} sessionToken - Token de sesión actual (si existe)
     * @returns {Promise<Object>} Resultado de la verificación
     */
    async checkAccessCodeEligibility(email, deviceFingerprint, sessionToken = null) {
        // Buscar códigos activos (no usados y no expirados)
        const activeCodesQuery = `
            SELECT code, device_fingerprint, session_token, created_at, expires_at
            FROM access_codes 
            WHERE email = $1 
            AND used_at IS NULL 
            AND expires_at > NOW()
            ORDER BY created_at DESC
        `;
        
        const activeCodes = await this.getMany(activeCodesQuery, [email]);
        
        if (activeCodes.length === 0) {
            return { allowed: true, reason: 'no_active_codes' };
        }
        
        const latestCode = activeCodes[0];
        
        // Si tiene session token y coincide con el del código existente = renovación
        if (sessionToken && latestCode.session_token === sessionToken) {
            return { 
                allowed: true, 
                reason: 'session_renewal',
                existingCode: latestCode.code
            };
        }
        
        // Si el fingerprint coincide = mismo dispositivo
        if (latestCode.device_fingerprint === deviceFingerprint) {
            return { 
                allowed: true, 
                reason: 'same_device',
                existingCode: latestCode.code
            };
        }
        
        // Diferente dispositivo y no es renovación = bloquear
        return { 
            allowed: false, 
            reason: 'multiple_sessions_blocked',
            blockedUntil: latestCode.expires_at
        };
    }

    /**
     * Genera código de acceso con control de sesiones
     */
    async generateAccessCodeWithSessionControl(email, deviceFingerprint, sessionToken = null) {
        // Verificar elegibilidad
        const eligibility = await this.checkAccessCodeEligibility(email, deviceFingerprint, sessionToken);
        
        if (!eligibility.allowed) {
            throw new Error(`MULTIPLE_SESSIONS_BLOCKED:${eligibility.blockedUntil}`);
        }
        
        // Si hay código existente válido, reutilizar
        if (eligibility.existingCode) {
            await this.query(
                'UPDATE access_codes SET created_at = NOW() WHERE email = $1 AND code = $2',
                [email, eligibility.existingCode]
            );
            
            return {
                code: eligibility.existingCode,
                isRenewal: eligibility.reason === 'session_renewal',
                reason: eligibility.reason
            };
        }
        
        // Invalidar códigos anteriores
        await this.query(
            'UPDATE access_codes SET used_at = NOW() WHERE email = $1 AND used_at IS NULL',
            [email]
        );
        
        // Generar nuevo código
        const code = Math.random().toString(36).substring(2, 8).toUpperCase();
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutos
        
        const newSessionToken = sessionToken || crypto.randomUUID();
        
        await this.query(`
            INSERT INTO access_codes (email, code, expires_at, device_fingerprint, session_token, is_renewal, previous_session_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [email, code, expiresAt, deviceFingerprint, newSessionToken, eligibility.reason === 'session_renewal', sessionToken]);
        
        return {
            code,
            sessionToken: newSessionToken,
            expiresAt,
            isRenewal: false,
            reason: 'new_code_generated'
        };
    }

    /**
     * Verifica un código de acceso
     * @param {string} email - Email del usuario
     * @param {string} code - Código a verificar
     * @returns {Promise<boolean>} True si el código es válido
     */
    async verifyAccessCode(email, code) {
        const accessCode = await this.getOne(
            `SELECT * FROM access_codes 
             WHERE email = $1 AND code = $2 AND expires_at > NOW() AND used_at IS NULL`,
            [email, code]
        );

        if (accessCode) {
            // Marcar como usado
            await this.query(
                'UPDATE access_codes SET used_at = NOW() WHERE id = $1',
                [accessCode.id]
            );
            return true;
        }

        return false;
    }

    /**
     * Registra un evento en los logs de acceso
     * @param {Object} logData - Datos del log
     * @returns {Promise<void>}
     */
    async logAccess(logData) {
        const { email, action, ipAddress, userAgent, success, errorMessage } = logData;
        
        await this.query(
            'INSERT INTO access_logs (email, action, ip_address, user_agent, success, error_message) VALUES ($1, $2, $3, $4, $5, $6)',
            [email, action, ipAddress, userAgent, success, errorMessage]
        );
    }

    /**
     * Actualiza una suscripción
     * @param {string} subscriptionId - ID de la suscripción
     * @param {Object} updates - Campos a actualizar
     * @returns {Promise<boolean>} True si se actualizó
     */
    async updateSubscription(subscriptionId, updates) {
        const fields = [];
        const values = [];
        let paramIndex = 1;

        // Construir query dinámicamente
        Object.keys(updates).forEach(key => {
            const dbField = this.camelToSnakeCase(key);
            fields.push(`${dbField} = $${paramIndex}`);
            values.push(updates[key]);
            paramIndex++;
        });

        if (fields.length === 0) {
            return false;
        }

        values.push(subscriptionId);

        const result = await this.query(
            `UPDATE active_subscriptions SET ${fields.join(', ')} WHERE id = $${paramIndex}`,
            values
        );

        return result.rowCount > 0;
    }

    /**
     * Convierte camelCase a snake_case
     * @param {string} str - String en camelCase
     * @returns {string} String en snake_case
     */
    camelToSnakeCase(str) {
        return str.replace(/[A-Z]/g, letter => `_${letter.toLowerCase()}`);
    }

    /**
     * Genera código alfanumérico aleatorio
     * @param {number} length - Longitud del código
     * @returns {string} Código generado
     */
    generateRandomCode(length = 8) {
        const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Sin caracteres confusos
        let result = '';
        
        for (let i = 0; i < length; i++) {
            result += chars.charAt(Math.floor(Math.random() * chars.length));
        }
        
        return result;
    }

    /**
     * Obtiene estadísticas del sistema
     * @returns {Promise<Object>} Estadísticas
     */
    async getSystemStats() {
        const [
            totalSubs,
            activeSubs,
            expiringSubs,
            recentAccess,
            topUsers
        ] = await Promise.all([
            this.getOne('SELECT COUNT(*) as count FROM active_subscriptions'),
            this.getOne('SELECT COUNT(*) as count FROM active_subscriptions WHERE status = $1 AND end_date > CURRENT_DATE', ['active']),
            this.getOne('SELECT COUNT(*) as count FROM active_subscriptions WHERE status = $1 AND end_date BETWEEN CURRENT_DATE AND CURRENT_DATE + INTERVAL \'7 days\'', ['active']),
            this.getMany('SELECT email, COUNT(*) as access_count FROM access_logs WHERE created_at > NOW() - INTERVAL \'24 hours\' AND success = true GROUP BY email ORDER BY access_count DESC LIMIT 10'),
            this.getMany('SELECT email, COUNT(*) as total_access FROM access_logs WHERE success = true GROUP BY email ORDER BY total_access DESC LIMIT 10')
        ]);

        return {
            subscriptions: {
                total: parseInt(totalSubs.count),
                active: parseInt(activeSubs.count),
                expiringThisWeek: parseInt(expiringSubs.count)
            },
            recentActivity: {
                last24Hours: recentAccess,
                topUsers: topUsers
            }
        };
    }

    /**
     * Crea o actualiza una sesión activa
     * @param {Object} sessionData - Datos de la sesión
     * @returns {Promise<string>} Session token
     */
    async createActiveSession(sessionData) {
        const {
            email,
            deviceFingerprint,
            jwtTokenHash,
            ipAddress,
            userAgent,
            deviceInfo,
            expiresAt
        } = sessionData;

        const sessionToken = crypto.randomUUID();

        // Usar UPSERT para actualizar si ya existe la combinación email+fingerprint
        await this.query(`
            INSERT INTO active_sessions
            (email, device_fingerprint, session_token, jwt_token_hash, ip_address, user_agent, device_info, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            ON CONFLICT (email, device_fingerprint)
            DO UPDATE SET
                session_token = EXCLUDED.session_token,
                jwt_token_hash = EXCLUDED.jwt_token_hash,
                ip_address = EXCLUDED.ip_address,
                user_agent = EXCLUDED.user_agent,
                device_info = EXCLUDED.device_info,
                last_activity = NOW(),
                expires_at = EXCLUDED.expires_at
        `, [email, deviceFingerprint, sessionToken, jwtTokenHash, ipAddress, userAgent, JSON.stringify(deviceInfo), expiresAt]);

        return sessionToken;
    }

    /**
     * Valida que solo exista una sesión activa por usuario
     * @param {string} email - Email del usuario
     * @param {string} deviceFingerprint - Fingerprint del dispositivo
     * @param {string} jwtTokenHash - Hash del JWT actual
     * @returns {Promise<Object>} Resultado de validación
     */
    async validateSingleSession(email, deviceFingerprint, jwtTokenHash) {
        // Limpiar sesiones expiradas primero
        await this.query(
            'DELETE FROM active_sessions WHERE expires_at < NOW()'
        );

        // Buscar sesiones activas para este email
        const activeSessions = await this.getMany(
            'SELECT * FROM active_sessions WHERE email = $1 AND expires_at > NOW()',
            [email]
        );

        if (activeSessions.length === 0) {
            return { valid: true, reason: 'no_active_sessions' };
        }

        // Si hay sesión con mismo fingerprint y token hash, es válida
        const matchingSession = activeSessions.find(
            s => s.device_fingerprint === deviceFingerprint && s.jwt_token_hash === jwtTokenHash
        );

        if (matchingSession) {
            // Actualizar última actividad
            await this.query(
                'UPDATE active_sessions SET last_activity = NOW() WHERE id = $1',
                [matchingSession.id]
            );
            return { valid: true, reason: 'same_device_session', session: matchingSession };
        }

        // Si hay sesión con mismo fingerprint pero diferente token (renovación)
        const sameDeviceSession = activeSessions.find(
            s => s.device_fingerprint === deviceFingerprint
        );

        if (sameDeviceSession) {
            return { valid: true, reason: 'same_device_new_token', session: sameDeviceSession };
        }

        // Hay sesión activa en otro dispositivo
        return {
            valid: false,
            reason: 'session_exists_another_device',
            blockedUntil: activeSessions[0].expires_at,
            activeDevice: {
                fingerprint: activeSessions[0].device_fingerprint,
                lastActivity: activeSessions[0].last_activity,
                ipAddress: activeSessions[0].ip_address
            }
        };
    }

    /**
     * Invalida sesión activa de un usuario
     * @param {string} email - Email del usuario
     * @param {string} deviceFingerprint - Fingerprint opcional para invalidar dispositivo específico
     * @returns {Promise<number>} Número de sesiones invalidadas
     */
    async invalidateSession(email, deviceFingerprint = null) {
        if (deviceFingerprint) {
            const result = await this.query(
                'DELETE FROM active_sessions WHERE email = $1 AND device_fingerprint = $2',
                [email, deviceFingerprint]
            );
            return result.rowCount;
        } else {
            const result = await this.query(
                'DELETE FROM active_sessions WHERE email = $1',
                [email]
            );
            return result.rowCount;
        }
    }

    /**
     * Obtiene sesiones activas de un usuario
     * @param {string} email - Email del usuario
     * @returns {Promise<Array>} Sesiones activas
     */
    async getActiveSessions(email) {
        return await this.getMany(
            `SELECT id, device_fingerprint, ip_address, user_agent, device_info,
                    last_activity, expires_at, created_at
             FROM active_sessions
             WHERE email = $1 AND expires_at > NOW()
             ORDER BY last_activity DESC`,
            [email]
        );
    }

    /**
     * Limpia sesiones expiradas (ejecutar periódicamente)
     * @returns {Promise<number>} Número de sesiones eliminadas
     */
    async cleanExpiredSessions() {
        const result = await this.query(
            'DELETE FROM active_sessions WHERE expires_at < NOW()'
        );

        if (result.rowCount > 0) {
            logger.info(`Limpiadas ${result.rowCount} sesiones expiradas`, {
                sessionsRemoved: result.rowCount
            });
        }

        return result.rowCount;
    }

    /**
     * Cierra el pool de conexiones
     * @returns {Promise<void>}
     */
    async close() {
        if (this.pool) {
            await this.pool.end();
            logger.info('Pool de conexiones PostgreSQL cerrado');
        }
    }

    /**
     * Obtiene información del estado de la conexión
     * @returns {Object} Estado de la conexión
     */
    getConnectionInfo() {
        if (!this.pool) {
            return { connected: false };
        }

        return {
            connected: true,
            totalCount: this.pool.totalCount,
            idleCount: this.pool.idleCount,
            waitingCount: this.pool.waitingCount
        };
    }
}

export default PostgreSQLManager;