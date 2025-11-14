#!/usr/bin/env node

/**
 * Script para extender suscripciones manualmente
 * Uso: node extend-subscription.js <email> <meses>
 * Ejemplo: node extend-subscription.js victorrosso2311@gmail.com 1
 */

import dotenv from 'dotenv';
import PostgreSQLManager from './src/database/PostgreSQLManager.js';

dotenv.config();

async function extendSubscription(email, monthsToAdd = 1) {
    const db = new PostgreSQLManager();

    try {
        console.log('🔄 Conectando a la base de datos...');
        await db.initialize();

        // Buscar la suscripción actual
        console.log(`🔍 Buscando suscripción para: ${email}`);
        const result = await db.query(
            'SELECT * FROM active_subscriptions WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            console.error(`❌ No se encontró ninguna suscripción para: ${email}`);
            process.exit(1);
        }

        const subscription = result.rows[0];
        console.log('\n📋 Suscripción actual:');
        console.log(`   ID: ${subscription.id}`);
        console.log(`   Email: ${subscription.email}`);
        console.log(`   Nombre: ${subscription.customer_name}`);
        console.log(`   Estado: ${subscription.status}`);
        console.log(`   Fecha inicio: ${subscription.start_date}`);
        console.log(`   Fecha fin actual: ${subscription.end_date}`);

        // Calcular nueva fecha de fin
        const currentEndDate = new Date(subscription.end_date);
        const newEndDate = new Date(currentEndDate);
        newEndDate.setMonth(newEndDate.getMonth() + monthsToAdd);

        console.log(`\n➡️  Nueva fecha de fin: ${newEndDate.toISOString().split('T')[0]}`);
        console.log(`   (Extensión de ${monthsToAdd} ${monthsToAdd === 1 ? 'mes' : 'meses'})`);

        // Actualizar la suscripción
        const updated = await db.updateSubscription(subscription.id, {
            endDate: newEndDate.toISOString().split('T')[0],
            status: 'active', // Asegurar que esté activa
            updatedAt: new Date()
        });

        if (updated) {
            console.log('\n✅ Suscripción extendida exitosamente');

            // Verificar el cambio
            const verifyResult = await db.query(
                'SELECT email, customer_name, start_date, end_date, status FROM active_subscriptions WHERE id = $1',
                [subscription.id]
            );

            console.log('\n📋 Suscripción actualizada:');
            const updatedSub = verifyResult.rows[0];
            console.log(`   Email: ${updatedSub.email}`);
            console.log(`   Nombre: ${updatedSub.customer_name}`);
            console.log(`   Estado: ${updatedSub.status}`);
            console.log(`   Fecha inicio: ${updatedSub.start_date}`);
            console.log(`   Fecha fin: ${updatedSub.end_date}`);
        } else {
            console.error('❌ No se pudo actualizar la suscripción');
            process.exit(1);
        }

    } catch (error) {
        console.error('❌ Error extendiendo suscripción:', error.message);
        process.exit(1);
    } finally {
        if (db.pool) {
            await db.pool.end();
            console.log('\n🔌 Conexión cerrada');
        }
    }
}

// Leer argumentos de línea de comandos
const args = process.argv.slice(2);

if (args.length < 1) {
    console.log('Uso: node extend-subscription.js <email> [meses]');
    console.log('Ejemplo: node extend-subscription.js victorrosso2311@gmail.com 1');
    process.exit(1);
}

const email = args[0];
const monthsToAdd = args[1] ? parseInt(args[1]) : 1;

if (isNaN(monthsToAdd) || monthsToAdd < 1) {
    console.error('❌ El número de meses debe ser un número positivo');
    process.exit(1);
}

// Ejecutar
extendSubscription(email, monthsToAdd);
