import winston from 'winston';
import DailyRotateFile from 'winston-daily-rotate-file';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Obtener __dirname para ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const projectRoot = join(__dirname, '..', '..');
const logsDir = join(projectRoot, 'logs');

/**
 * Formato personalizado para logs
 */
const customFormat = winston.format.combine(
    winston.format.timestamp({
        format: 'YYYY-MM-DD HH:mm:ss.SSS'
    }),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.printf(({ timestamp, level, message, module, ...metadata }) => {
        let msg = `[${timestamp}] [${level.toUpperCase()}] [${module || 'SYSTEM'}] ${message}`;

        // Agregar metadata si existe
        const metaKeys = Object.keys(metadata);
        if (metaKeys.length > 0) {
            // Excluir 'stack' del metadata general para evitar duplicados
            const filteredMeta = { ...metadata };
            delete filteredMeta.stack;

            if (Object.keys(filteredMeta).length > 0) {
                msg += ` ${JSON.stringify(filteredMeta)}`;
            }
        }

        // Agregar stack trace si existe
        if (metadata.stack) {
            msg += `\n${metadata.stack}`;
        }

        return msg;
    })
);

/**
 * Configuración de transports para logs normales
 */
const infoTransport = new DailyRotateFile({
    filename: join(logsDir, 'app-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '30d',
    level: 'info',
    format: customFormat,
    zippedArchive: true
});

/**
 * Configuración de transports para logs de error
 */
const errorTransport = new DailyRotateFile({
    filename: join(logsDir, 'error-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '30d',
    level: 'error',
    format: customFormat,
    zippedArchive: true
});

/**
 * Configuración de transports para logs de debug (desarrollo)
 */
const debugTransport = new DailyRotateFile({
    filename: join(logsDir, 'debug-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    maxSize: '20m',
    maxFiles: '7d',
    level: 'debug',
    format: customFormat,
    zippedArchive: true
});

/**
 * Configuración de transport para consola
 */
const consoleTransport = new winston.transports.Console({
    format: winston.format.combine(
        winston.format.colorize(),
        winston.format.timestamp({
            format: 'HH:mm:ss'
        }),
        winston.format.printf(({ timestamp, level, message, module }) => {
            return `[${timestamp}] ${level} [${module || 'SYSTEM'}] ${message}`;
        })
    )
});

/**
 * Logger principal de Winston
 */
const winstonLogger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    transports: [
        infoTransport,
        errorTransport,
        debugTransport,
        consoleTransport
    ],
    exitOnError: false
});

/**
 * Clase Logger que encapsula Winston y agrega funcionalidad de módulos
 */
class Logger {
    constructor(moduleName = 'SYSTEM') {
        this.moduleName = moduleName;
    }

    /**
     * Registra mensaje de nivel info
     * @param {string} message - Mensaje a registrar
     * @param {Object} metadata - Metadata adicional
     */
    info(message, metadata = {}) {
        winstonLogger.info(message, { module: this.moduleName, ...metadata });
    }

    /**
     * Registra mensaje de nivel error
     * @param {string} message - Mensaje a registrar
     * @param {Error|Object} error - Error o metadata
     */
    error(message, error = {}) {
        if (error instanceof Error) {
            winstonLogger.error(message, {
                module: this.moduleName,
                error: error.message,
                stack: error.stack,
                code: error.code
            });
        } else {
            winstonLogger.error(message, { module: this.moduleName, ...error });
        }
    }

    /**
     * Registra mensaje de nivel warn
     * @param {string} message - Mensaje a registrar
     * @param {Object} metadata - Metadata adicional
     */
    warn(message, metadata = {}) {
        winstonLogger.warn(message, { module: this.moduleName, ...metadata });
    }

    /**
     * Registra mensaje de nivel debug
     * @param {string} message - Mensaje a registrar
     * @param {Object} metadata - Metadata adicional
     */
    debug(message, metadata = {}) {
        winstonLogger.debug(message, { module: this.moduleName, ...metadata });
    }

    /**
     * Registra operación de base de datos
     * @param {string} operation - Tipo de operación
     * @param {string} table - Tabla afectada
     * @param {Object} details - Detalles adicionales
     */
    database(operation, table, details = {}) {
        this.info(`DB ${operation}: ${table}`, {
            operation,
            table,
            ...details
        });
    }

    /**
     * Registra request HTTP
     * @param {Object} req - Express request object
     * @param {number} statusCode - Código de respuesta
     * @param {number} duration - Duración en ms
     */
    http(req, statusCode, duration) {
        const level = statusCode >= 400 ? 'warn' : 'info';
        winstonLogger[level](`${req.method} ${req.path} ${statusCode} ${duration}ms`, {
            module: this.moduleName,
            method: req.method,
            path: req.path,
            statusCode,
            duration,
            ip: req.ip,
            userAgent: req.get('User-Agent')
        });
    }

    /**
     * Registra evento de seguridad
     * @param {string} event - Tipo de evento
     * @param {Object} details - Detalles del evento
     */
    security(event, details = {}) {
        winstonLogger.warn(`SECURITY: ${event}`, {
            module: this.moduleName,
            event,
            ...details
        });
    }

    /**
     * Registra evento de autenticación
     * @param {string} action - Acción (login, logout, etc)
     * @param {string} email - Email del usuario
     * @param {boolean} success - Si fue exitoso
     * @param {Object} details - Detalles adicionales
     */
    auth(action, email, success, details = {}) {
        const level = success ? 'info' : 'warn';
        winstonLogger[level](`AUTH ${action}: ${email} - ${success ? 'SUCCESS' : 'FAILED'}`, {
            module: this.moduleName,
            action,
            email,
            success,
            ...details
        });
    }

    /**
     * Registra evento de email
     * @param {string} to - Destinatario
     * @param {string} subject - Asunto
     * @param {boolean} success - Si fue exitoso
     * @param {Object} details - Detalles adicionales
     */
    email(to, subject, success, details = {}) {
        const level = success ? 'info' : 'error';
        winstonLogger[level](`EMAIL to ${to}: ${subject} - ${success ? 'SENT' : 'FAILED'}`, {
            module: this.moduleName,
            to,
            subject,
            success,
            ...details
        });
    }
}

/**
 * Factory para crear loggers con nombre de módulo
 * @param {string} moduleName - Nombre del módulo
 * @returns {Logger} Instancia de Logger
 */
export function createLogger(moduleName) {
    return new Logger(moduleName);
}

/**
 * Logger por defecto del sistema
 */
export const systemLogger = new Logger('SYSTEM');

/**
 * Exportar instancia de winston para casos especiales
 */
export { winstonLogger };

export default Logger;
