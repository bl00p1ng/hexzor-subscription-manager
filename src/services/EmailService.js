import nodemailer from 'nodemailer';

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
        this.fromName = process.env.FROM_NAME || 'Nexos Cookies Tool';
    }

    /**
     * Inicializa el servicio de email
     * @returns {Promise<void>}
     */
    async initialize() {
        try {
            if (!this.config.auth.user || !this.config.auth.pass) {
                console.warn('⚠️ Configuración SMTP incompleta - emails no funcionarán');
                return;
            }

            this.transporter = nodemailer.createTransporter(this.config);
            
            // Verificar conexión SMTP
            await this.transporter.verify();
            console.log('✅ Servicio de email inicializado correctamente');
            
        } catch (error) {
            console.error('❌ Error inicializando servicio de email:', error.message);
            console.log('📧 Los emails no estarán disponibles hasta configurar SMTP');
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
            console.warn(`⚠️ No se puede enviar email a ${email} - SMTP no configurado`);
            console.log(`🔑 Código para ${email}: ${code} (válido por 10 minutos)`);
            return false;
        }

        try {
            const htmlContent = this.generateAccessCodeEmail(code, customerName);
            const textContent = this.generateAccessCodeTextEmail(code, customerName);

            const mailOptions = {
                from: `"${this.fromName}" <${this.fromEmail}>`,
                to: email,
                subject: 'Tu código de acceso - Nexos Cookies Tool',
                text: textContent,
                html: htmlContent
            };

            const result = await this.transporter.sendMail(mailOptions);
            console.log(`📧 Email enviado a ${email} - ID: ${result.messageId}`);
            
            return true;

        } catch (error) {
            console.error(`❌ Error enviando email a ${email}:`, error.message);
            
            // Fallback: mostrar código en consola para desarrollo
            console.log(`🔑 Código para ${email}: ${code} (válido por 10 minutos)`);
            
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
    <title>Código de Acceso - Nexos Cookies Tool</title>
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
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px 20px;
            text-align: center;
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 300;
        }
        .content {
            padding: 30px 20px;
        }
        .code-container {
            background: #f8f9fa;
            border: 2px dashed #6c757d;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
            margin: 20px 0;
        }
        .access-code {
            font-size: 32px;
            font-weight: bold;
            color: #495057;
            letter-spacing: 4px;
            font-family: 'Courier New', monospace;
        }
        .warning {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 6px;
            padding: 15px;
            margin: 20px 0;
            color: #856404;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            font-size: 14px;
        }
        .button {
            display: inline-block;
            background: #667eea;
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
            <h1>🍪 Nexos Cookies Tool</h1>
            <p>Tu código de acceso está listo</p>
        </div>
        
        <div class="content">
            <h2>Hola ${customerName},</h2>
            
            <p>Has solicitado acceso a <strong>Nexos Cookies Tool</strong>. Utiliza el siguiente código para completar tu autenticación:</p>
            
            <div class="code-container">
                <div class="access-code">${code}</div>
                <p style="margin: 10px 0 0 0; color: #6c757d;">Código de acceso</p>
            </div>
            
            <div class="warning">
                <strong>⚠️ Importante:</strong>
                <ul style="margin: 10px 0; padding-left: 20px;">
                    <li>Este código es válido por <strong>10 minutos</strong></li>
                    <li>Solo puede ser usado una vez</li>
                    <li>No compartas este código con nadie</li>
                    <li>Si no solicitaste este código, ignora este email</li>
                </ul>
            </div>
            
            <p>Si tienes algún problema para acceder, contacta a nuestro equipo de soporte.</p>
            
            <p>¡Gracias por confiar en nosotros!</p>
        </div>
        
        <div class="footer">
            <p>Este email fue enviado automáticamente. Por favor no respondas a este mensaje.</p>
            <p>&copy; ${new Date().getFullYear()} Nexos Cookies Tool. Todos los derechos reservados.</p>
        </div>
    </div>
</body>
</html>`;
    }

    /**
     * Genera el contenido de texto plano del email
     * @param {string} code - Código de acceso
     * @param {string} customerName - Nombre del cliente
     * @returns {string} Contenido de texto
     */
    generateAccessCodeTextEmail(code, customerName) {
        return `
NEXOS COOKIES TOOL - CÓDIGO DE ACCESO

Hola ${customerName},

Has solicitado acceso a Nexos Cookies Tool. 

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
© ${new Date().getFullYear()} Nexos Cookies Tool. Todos los derechos reservados.
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
                subject: 'Nuevo acceso a Nexos Cookies Tool',
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
            console.error('Error enviando notificación a admin:', error.message);
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