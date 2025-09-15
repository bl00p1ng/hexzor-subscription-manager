import { createInterface } from 'readline';
import { promises as fs } from 'fs';
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

        // Verificar si el email ya existe
        const existingEmail = await this.db.getOne('SELECT id FROM admin_users WHERE email = ?', [email]);
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
            const testEmail = await this.askQuestion('Email para prueba: ');
            
            if (this.isValidEmail(testEmail)) {
                // Aquí podrías importar y probar EmailService
                console.log('📧 Enviando email de prueba...');
                console.log('(Para implementar: importar EmailService y enviar email de prueba)');
            } else {
                console.log('❌ Email inválido para prueba');
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
        console.log('');
        console.log('✅ Sistema de autenticación configurado correctamente');
        console.log('');
        console.log('📋 Próximos pasos:');
        console.log('1. Iniciar el servidor: npm start');
        console.log('2. Acceder al panel admin: http://localhost:3001');
        console.log('3. Gestionar suscripciones desde el panel');
        console.log('4. Integrar con la aplicación principal');
        console.log('');
        console.log('🔧 URLs importantes:');
        console.log(`   Panel Admin: http://localhost:${process.env.PORT || 3001}`);
        console.log(`   API Health: http://localhost:${process.env.PORT || 3001}/health`);
        console.log(`   API Auth: http://localhost:${process.env.PORT || 3001}/api/auth`);
        console.log('');
        console.log('📖 Documentación de la API disponible en el README.md');
        console.log('');
    }

    /**
     * Genera un JWT_SECRET aleatorio si no existe
     */
    async generateJWTSecret() {
        const secret = crypto.randomBytes(64).toString('hex');
        console.log('🔑 JWT_SECRET generado:');
        console.log(secret);
        console.log('');
        console.log('Agrega esta línea a tu archivo .env:');
        console.log(`JWT_SECRET=${secret}`);
        return secret;
    }

    /**
     * Hace una pregunta al usuario y retorna la respuesta
     * @param {string} question - Pregunta a hacer
     * @returns {Promise<string>} Respuesta del usuario
     */
    askQuestion(question) {
        return new Promise((resolve) => {
            this.rl.question(question, (answer) => {
                resolve(answer.trim());
            });
        });
    }

    /**
     * Hace una pregunta de contraseña (oculta la entrada)
     * @param {string} question - Pregunta a hacer
     * @returns {Promise<string>} Respuesta del usuario
     */
    askPasswordQuestion(question) {
        return new Promise((resolve) => {
            process.stdout.write(question);
            
            // Ocultar entrada
            process.stdin.setRawMode(true);
            process.stdin.resume();
            process.stdin.setEncoding('utf8');
            
            let password = '';
            
            process.stdin.on('data', (char) => {
                char = char.toString();
                
                if (char === '\r' || char === '\n') {
                    // Enter presionado
                    process.stdin.setRawMode(false);
                    process.stdin.pause();
                    process.stdout.write('\n');
                    process.stdin.removeAllListeners('data');
                    resolve(password);
                } else if (char === '\u0003') {
                    // Ctrl+C presionado
                    process.exit(1);
                } else if (char === '\u007f') {
                    // Backspace presionado
                    if (password.length > 0) {
                        password = password.slice(0, -1);
                        process.stdout.write('\b \b');
                    }
                } else {
                    // Carácter normal
                    password += char;
                    process.stdout.write('*');
                }
            });
        });
    }

    /**
     * Valida si un email es válido
     * @param {string} email - Email a validar
     * @returns {boolean} True si es válido
     */
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    /**
     * Cierra la conexión a la base de datos
     */
    async cleanup() {
        if (this.db) {
            await this.db.close();
        }
    }
}

// Ejecutar wizard si el archivo se ejecuta directamente
if (import.meta.url === `file://${process.argv[1]}`) {
    const wizard = new SetupWizard();
    
    // Manejo de cierre elegante
    process.on('SIGINT', async () => {
        console.log('\n\n🛑 Configuración cancelada por el usuario');
        await wizard.cleanup();
        process.exit(0);
    });

    process.on('SIGTERM', async () => {
        await wizard.cleanup();
        process.exit(0);
    });

    // Ejecutar wizard
    wizard.run().then(async () => {
        await wizard.cleanup();
        process.exit(0);
    }).catch(async (error) => {
        console.error('Error en wizard:', error.message);
        await wizard.cleanup();
        process.exit(1);
    });
}

export default SetupWizard;