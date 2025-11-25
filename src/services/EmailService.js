import nodemailer from 'nodemailer';
import { createLogger } from './Logger.js';

const logger = createLogger('EMAIL');

/**
 * Servicio de envío de emails para códigos de acceso
 * Configurable para diferentes proveedores SMTP
 */
class EmailService {
    constructor() {
        this.transporter = null;
        this.config = {
            host: process.env.SMTP_HOST || 'smtp.gmail.com',
            port: parseInt(process.env.SMTP_PORT) || 587,
            secure: process.env.SMTP_SECURE === 'true' || false,
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        };
        
        this.fromEmail = process.env.FROM_EMAIL || process.env.SMTP_USER;
        this.fromName = process.env.FROM_NAME || 'Hexzor Cookies Tool';
    }

    /**
     * Inicializa el servicio de email
     * @returns {Promise<void>}
     */
    async initialize() {
        try {
            if (!this.config.auth.user || !this.config.auth.pass) {
                logger.warn('Configuración SMTP incompleta - emails no funcionarán');
                return;
            }

            this.transporter = nodemailer.createTransport(this.config);

            // Verificar conexión SMTP
            await this.transporter.verify();
            logger.info('Servicio de email inicializado correctamente', {
                host: this.config.host,
                port: this.config.port,
                secure: this.config.secure
            });

        } catch (error) {
            logger.error('Error inicializando servicio de email', error);
            logger.warn('Los emails no estarán disponibles hasta configurar SMTP');
        }
    }

    /**
     * Envía un código de acceso por email
     * @param {string} email - Email destino
     * @param {string} code - Código de acceso
     * @param {string} customerName - Nombre del cliente (opcional)
     * @returns {Promise<boolean>} True si se envió correctamente
     */
    async sendAccessCode(email, code, customerName = 'Usuario') {
        if (!this.transporter) {
            logger.warn('No se puede enviar email - SMTP no configurado', { to: email });
            logger.info(`🔑 Código para ${email}: ${code} (válido por 10 minutos)`, {
                to: email,
                code,
                validityMinutes: 10
            });
            return false;
        }

        try {
            const htmlContent = this.generateAccessCodeEmail(code, customerName);
            const textContent = this.generateAccessCodeTextEmail(code, customerName);

            const mailOptions = {
                from: `"${this.fromName}" <${this.fromEmail}>`,
                to: email,
                subject: 'Tu código de acceso - Hexzor Cookies Tool',
                text: textContent,
                html: htmlContent
            };

            const result = await this.transporter.sendMail(mailOptions);
            logger.email(email, 'Código de acceso', true, {
                messageId: result.messageId,
                customerName
            });

            return true;

        } catch (error) {
            logger.email(email, 'Código de acceso', false, {
                error: error.message,
                code: error.code
            });

            // Fallback: mostrar código en consola para desarrollo
            logger.info(`🔑 FALLBACK - Código para ${email}: ${code} (válido por 10 minutos)`, {
                to: email,
                code,
                validityMinutes: 10
            });

            return false;
        }
    }

    /**
     * Genera el contenido HTML del email del código de acceso
     * @param {string} code - Código de acceso
     * @param {string} customerName - Nombre del cliente
     * @returns {string} Contenido HTML
     */
    generateAccessCodeEmail(code, customerName) {
        return `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Código de Acceso - Hexzor Cookies Tool</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            background: white;
            border-radius: 10px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            margin-bottom: 30px;
        }
        .logo {
            font-size: 24px;
            font-weight: bold;
            color: #2563eb;
            margin-bottom: 10px;
        }
        .code-container {
            background: #f8fafc;
            border: 2px dashed #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 25px 0;
        }
        .access-code {
            font-size: 32px;
            font-weight: bold;
            color: #1e40af;
            letter-spacing: 4px;
            margin: 10px 0;
            font-family: 'Courier New', monospace;
        }
        .warning {
            background: #fef3c7;
            border: 1px solid #f59e0b;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
        }
        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            text-align: center;
            font-size: 14px;
            color: #6b7280;
        }
        .button {
            display: inline-block;
            background: #2563eb;
            color: white;
            padding: 12px 24px;
            text-decoration: none;
            border-radius: 6px;
            margin: 10px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">Cookies Hexzor</div>
            <h1>Código de Acceso</h1>
            <p>Hola ${customerName},</p>
            <p>Aquí tienes tu código de acceso temporal para ingresar a la aplicación:</p>
        </div>

        <div class="code-container">
            <p><strong>Tu código de acceso es:</strong></p>
            <div class="access-code">${code}</div>
            <p><small>Válido por 10 minutos</small></p>
        </div>

        <div class="warning">
            <h3>⚠️ Importante:</h3>
            <ul>
                <li>Este código es válido por <strong>10 minutos</strong></li>
                <li>Solo puede ser usado <strong>una vez</strong></li>
                <li>No compartas este código con nadie</li>
                <li>Si no solicitaste este código, ignora este email</li>
            </ul>
        </div>

        <p>Ingresa este código en la aplicación para completar tu autenticación.</p>
        <p>Si tienes algún problema para acceder, contacta a nuestro equipo de soporte.</p>
        <p>¡Gracias por confiar en nosotros!</p>

        <div class="footer">
            <p>Este email fue enviado automáticamente. Por favor no respondas a este mensaje.</p>
            <p>© ${new Date().getFullYear()} Cookies Hexzor. Todos los derechos reservados.</p>
        </div>
    </div>
</body>
</html>`;
    }

    /**
     * Genera el contenido de texto plano del email del código de acceso
     * @param {string} code - Código de acceso
     * @param {string} customerName - Nombre del cliente
     * @returns {string} Contenido de texto plano
     */
    generateAccessCodeTextEmail(code, customerName) {
        return `
COOKIES HEXZOR
CÓDIGO DE ACCESO

Hola ${customerName},

TU CÓDIGO DE ACCESO: ${code}

IMPORTANTE:
- Este código es válido por 10 minutos
- Solo puede ser usado una vez
- No compartas este código con nadie
- Si no solicitaste este código, ignora este email

Ingresa este código en la aplicación para completar tu autenticación.

Si tienes algún problema para acceder, contacta a nuestro equipo de soporte.

¡Gracias por confiar en nosotros!

---
Este email fue enviado automáticamente. Por favor no respondas a este mensaje.
© ${new Date().getFullYear()} Cookies Hexzor. Todos los derechos reservados.
        `.trim();
    }

    /**
     * Envía notificación al administrador sobre nuevo acceso
     * @param {string} userEmail - Email del usuario que accedió
     * @param {string} ipAddress - IP del usuario
     * @returns {Promise<boolean>} True si se envió correctamente
     */
    async sendAdminNotification(userEmail, ipAddress) {
        if (!this.transporter || !process.env.ADMIN_EMAIL) {
            return false;
        }

        try {
            const mailOptions = {
                from: `"${this.fromName}" <${this.fromEmail}>`,
                to: process.env.ADMIN_EMAIL,
                subject: 'Nuevo acceso a Cookies Hexzor',
                text: `
Nuevo acceso detectado:

Usuario: ${userEmail}
IP: ${ipAddress}
Fecha: ${new Date().toLocaleString('es-ES')}

Este es un email automático de notificación.
                `.trim()
            };

            await this.transporter.sendMail(mailOptions);
            return true;

        } catch (error) {
            logger.error('Error enviando notificación a admin', error);
            return false;
        }
    }

    /**
     * Verifica la configuración del servicio de email
     * @returns {boolean} True si está configurado correctamente
     */
    isConfigured() {
        return !!(this.transporter && this.config.auth.user && this.config.auth.pass);
    }

    /**
     * Obtiene información del estado del servicio
     * @returns {Object} Estado del servicio
     */
    getStatus() {
        return {
            configured: this.isConfigured(),
            host: this.config.host,
            port: this.config.port,
            secure: this.config.secure,
            fromEmail: this.fromEmail,
            fromName: this.fromName
        };
    }
}

export default EmailService;