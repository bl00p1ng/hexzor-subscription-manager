import pg from 'pg';
import bcrypt from 'bcryptjs';

const { Pool } = pg;

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
            database: process.env.DB_NAME || 'hexzor_auth',
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
            console.log('✅ Conexión a PostgreSQL establecida');
            
            // Verificar versión
            const versionResult = await client.query('SELECT version()');
            console.log(`📊 PostgreSQL versión: ${versionResult.rows[0].version.split(' ')[1]}`);
            
            client.release();

            // Crear tablas si no existen
            await this.createTables();
            
            console.log('✅ Base de datos PostgreSQL inicializada');
        } catch (error) {
            console.error('❌ Error conectando a PostgreSQL:', error.message);
            console.log('💡 Sugerencias:');
            console.log('   1. Verificar que PostgreSQL esté ejecutándose');
            console.log('   2. Revisar credenciales en .env');
            console.log('   3. Verificar que la base de datos exista');
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
                'CREATE INDEX IF NOT EXISTS idx_admin_users_active ON admin_users(is_active)'
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
            console.log('✅ Tablas e índices creados correctamente');

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
            
            console.log('✅ Auto-migración: Control de sesiones aplicada');
        } catch (error) {
            await client.query('ROLLBACK');
            console.error('❌ Error creando tablas:', error.message);
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
            return result;
        } catch (error) {
            console.error('❌ Error en query PostgreSQL:', error.message);
            console.error('Query:', text);
            console.error('Params:', params);
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
     * Cierra el pool de conexiones
     * @returns {Promise<void>}
     */
    async close() {
        if (this.pool) {
            await this.pool.end();
            console.log('✅ Pool de conexiones PostgreSQL cerrado');
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