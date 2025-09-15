import { createInterface } from 'readline';
import PostgreSQLManager from '../database/PostgreSQLManager.js';
import dotenv from 'dotenv';
import crypto from 'crypto';

// Cargar variables de entorno
dotenv.config();

/**
 * Script de configuración inicial para el sistema de autenticación
 * Crea el primer usuario administrador y configura el sistema
 */
class SetupWizard {
    constructor() {
        this.rl = createInterface({
            input: process.stdin,
            output: process.stdout
        });
        this.db = new PostgreSQLManager();
    }

    /**
     * Ejecuta el wizard de configuración completo
     */
    async run() {
        try {
            console.log('🎯 WIZARD DE CONFIGURACIÓN INICIAL');
            console.log('═'.repeat(50));
            console.log('Este asistente te ayudará a configurar el sistema de autenticación');
            console.log('');

            // Verificar configuración
            await this.checkConfiguration();

            // Inicializar base de datos
            await this.initializeDatabase();

            // Crear administrador inicial
            await this.createInitialAdmin();

            // Verificar configuración de email
            await this.checkEmailConfiguration();

            // Mostrar resumen final
            this.showFinalSummary();

        } catch (error) {
            console.error('❌ Error en la configuración:', error.message);
            process.exit(1);
        } finally {
            this.rl.close();
        }
    }

    /**
     * Verifica la configuración básica del sistema
     */
    async checkConfiguration() {
        console.log('🔍 Verificando configuración...');
        
        const issues = [];

        // Verificar JWT_SECRET
        if (!process.env.JWT_SECRET) {
            issues.push('JWT_SECRET no configurado');
        } else if (process.env.JWT_SECRET.length < 32) {
            issues.push('JWT_SECRET muy corto (mínimo 32 caracteres)');
        }

        // Verificar configuración SMTP
        if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
            console.log('⚠️ Configuración SMTP incompleta - los emails no funcionarán');
        }

        if (issues.length > 0) {
            console.log('❌ Problemas de configuración encontrados:');
            issues.forEach(issue => console.log(`   • ${issue}`));
            console.log('');
            console.log('Por favor, corrige estos problemas en el archivo .env antes de continuar.');
            
            const shouldContinue = await this.askQuestion('¿Deseas continuar de todos modos? (y/N): ');
            if (shouldContinue.toLowerCase() !== 'y') {
                console.log('Configuración cancelada.');
                process.exit(0);
            }
        } else {
            console.log('✅ Configuración básica correcta');
        }
        console.log('');
    }

    /**
     * Inicializa la base de datos
     */
    async initializeDatabase() {
        console.log('🗄️ Inicializando base de datos...');
        
        try {
            await this.db.initialize();
            console.log('✅ Base de datos inicializada correctamente');
        } catch (error) {
            console.error('❌ Error inicializando base de datos:', error.message);
            throw error;
        }
        console.log('');
    }

    /**
     * Crea el usuario administrador inicial
     */
    async createInitialAdmin() {
        console.log('👨‍💼 Configuración del administrador inicial');
        console.log('─'.repeat(40));

        // Verificar si ya existe un administrador
        const existingAdmin = await this.db.getOne('SELECT COUNT(*) as count FROM admin_users');
        
        if (existingAdmin && existingAdmin.count > 0) {
            console.log('⚠️ Ya existe al menos un administrador en el sistema.');
            const shouldCreate = await this.askQuestion('¿Deseas crear otro administrador? (y/N): ');
            
            if (shouldCreate.toLowerCase() !== 'y') {
                console.log('Creación de administrador omitida.');
                return;
            }
        }

        // Solicitar datos del administrador
        const name = await this.askQuestion('Nombre completo del administrador: ');
        if (!name.trim()) {
            throw new Error('El nombre es obligatorio');
        }

        const email = await this.askQuestion('Email del administrador: ');
        if (!this.isValidEmail(email)) {
            throw new Error('Email inválido');
        }

        // Verificar si el email ya existe - LÍNEA CORREGIDA
        const existingEmail = await this.db.getOne('SELECT id FROM admin_users WHERE email = $1', [email]);
        if (existingEmail) {
            throw new Error('Ya existe un administrador con este email');
        }

        const password = await this.askPasswordQuestion('Contraseña (mínimo 8 caracteres): ');
        if (password.length < 8) {
            throw new Error('La contraseña debe tener al menos 8 caracteres');
        }

        const confirmPassword = await this.askPasswordQuestion('Confirmar contraseña: ');
        if (password !== confirmPassword) {
            throw new Error('Las contraseñas no coinciden');
        }

        // Crear administrador
        try {
            const adminId = await this.db.createAdminUser({
                email,
                password,
                name
            });

            console.log('✅ Administrador creado exitosamente');
            console.log(`   ID: ${adminId}`);
            console.log(`   Email: ${email}`);
            console.log(`   Nombre: ${name}`);

        } catch (error) {
            console.error('❌ Error creando administrador:', error.message);
            throw error;
        }
        console.log('');
    }

    /**
     * Verifica la configuración de email
     */
    async checkEmailConfiguration() {
        console.log('📧 Verificando configuración de email...');

        if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
            console.log('⚠️ SMTP no configurado - los emails no funcionarán');
            console.log('');
            console.log('Para configurar emails:');
            console.log('1. Edita el archivo .env');
            console.log('2. Configura SMTP_USER y SMTP_PASS');
            console.log('3. Reinicia el servidor');
            console.log('');
            return;
        }

        const shouldTest = await this.askQuestion('¿Deseas probar el envío de email? (y/N): ');
        if (shouldTest.toLowerCase() === 'y') {
            const testEmail = await this.askQuestion('Email de prueba: ');
            if (this.isValidEmail(testEmail)) {
                console.log('📧 Enviando email de prueba...');
                console.log('⚠️ Función de prueba no implementada aún');
            } else {
                console.log('❌ Email inválido');
            }
        }
        console.log('');
    }

    /**
     * Muestra el resumen final de la configuración
     */
    showFinalSummary() {
        console.log('🎉 CONFIGURACIÓN COMPLETADA');
        console.log('═'.repeat(50));
        console.log('✅ Base de datos inicializada');
        console.log('✅ Usuario administrador creado');
        console.log('');
        console.log('📋 Próximos pasos:');
        console.log('1. Ejecuta: npm start');
        console.log('2. Accede al panel de administración');
        console.log('3. Configura las suscripciones');
        console.log('');
        console.log('🔗 Endpoints disponibles:');
        console.log('   • POST /api/auth/admin/login - Login de administrador');
        console.log('   • POST /api/auth/request-access - Solicitar acceso');
        console.log('   • GET /api/status - Estado del servidor');
        console.log('');
    }

    /**
     * Realiza una pregunta al usuario y retorna la respuesta
     * @param {string} question - La pregunta a realizar
     * @returns {Promise<string>} La respuesta del usuario
     */
    askQuestion(question) {
        return new Promise((resolve) => {
            this.rl.question(question, (answer) => {
                resolve(answer.trim());
            });
        });
    }

    /**
     * Realiza una pregunta de contraseña (sin mostrar la entrada)
     * @param {string} question - La pregunta a realizar
     * @returns {Promise<string>} La contraseña ingresada
     */
    askPasswordQuestion(question) {
        return new Promise((resolve) => {
            process.stdout.write(question);
            
            // Deshabilitar echo para ocultar la contraseña
            process.stdin.setRawMode(true);
            process.stdin.resume();
            process.stdin.setEncoding('utf8');

            let password = '';
            const onData = (char) => {
                switch (char) {
                    case '\n':
                    case '\r':
                    case '\u0004': // Ctrl+D
                        process.stdin.setRawMode(false);
                        process.stdin.pause();
                        process.stdin.removeListener('data', onData);
                        console.log(''); // Nueva línea
                        resolve(password);
                        break;
                    case '\u0003': // Ctrl+C
                        process.exit(1);
                        break;
                    case '\u007f': // Backspace
                        if (password.length > 0) {
                            password = password.slice(0, -1);
                            process.stdout.write('\b \b');
                        }
                        break;
                    default:
                        password += char;
                        process.stdout.write('*');
                        break;
                }
            };

            process.stdin.on('data', onData);
        });
    }

    /**
     * Valida el formato de un email
     * @param {string} email - Email a validar
     * @returns {boolean} True si el email es válido
     */
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Genera un JWT_SECRET seguro si no existe
     * @returns {string} JWT_SECRET generado
     */
    generateJwtSecret() {
        return crypto.randomBytes(64).toString('hex');
    }
}

// Ejecutar el wizard si el archivo se ejecuta directamente
if (import.meta.url === `file://${process.argv[1]}`) {
    const wizard = new SetupWizard();
    wizard.run();
}