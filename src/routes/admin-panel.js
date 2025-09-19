import express from 'express';
import { authenticateAdmin } from '../middleware/auth.js';

const router = express.Router();

/**
 * Middleware para verificar autenticación en TODAS las rutas del panel
 * Si no está autenticado, redirige al login
 */
const requireAdminAuth = async (req, res, next) => {
    try {
        // Intentar verificar token de la cookie o header
        const token = req.cookies?.adminToken || req.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
            // No hay token, mostrar página de login
            return res.redirect('/admin/login');
        }

        // Verificar token usando el middleware existente
        req.headers.authorization = `Bearer ${token}`;
        
        // Usar el middleware de autenticación
        authenticateAdmin(req, res, (error) => {
            if (error || !req.admin) {
                // Token inválido, limpiar cookie y redirigir
                res.clearCookie('adminToken');
                return res.redirect('/admin/login');
            }
            next();
        });

    } catch (error) {
        res.clearCookie('adminToken');
        return res.redirect('/admin/login');
    }
};

/**
 * GET /admin/login
 * Página de login de administradores (única página pública)
 */
router.get('/login', (req, res) => {
    // Si ya está logueado, redirigir al dashboard
    if (req.cookies?.adminToken) {
        return res.redirect('/admin/dashboard');
    }

    res.send(`
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login Administrativo - Hexzor Cookies Tool</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background-color: #2762ea;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .login-container {
            background: rgba(255, 255, 255, 0.95);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 40px;
            max-width: 400px;
            width: 90%;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }

        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }

        .login-header h1 {
            color: #333;
            margin-bottom: 10px;
        }

        .login-header p {
            color: #666;
            font-size: 14px;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
            color: #555;
        }

        .form-group input {
            width: 100%;
            padding: 12px;
            border: 2px solid #e1e1e1;
            border-radius: 8px;
            font-size: 16px;
            transition: border-color 0.3s;
        }

        .form-group input:focus {
            outline: none;
            border-color: #2762ea;
        }

        .btn {
            background-color: #2762ea;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            transition: transform 0.2s;
            width: 100%;
        }

        .btn:hover {
            transform: translateY(-2px);
        }

        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }

        .alert {
            padding: 12px;
            border-radius: 8px;
            margin-bottom: 20px;
        }

        .alert.error {
            background: #fee;
            border: 1px solid #fcc;
            color: #c33;
        }

        .security-notice {
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            font-size: 12px;
            color: #666;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="login-header">
            <h1><i class="fas fa-shield-alt"></i> Acceso Administrativo</h1>
            <p>Panel de Control - Hexzor Cookies Tool</p>
        </div>

        <div id="alertContainer"></div>

        <form id="loginForm">
            <div class="form-group">
                <label for="email">Email de Administrador:</label>
                <input type="email" id="email" name="email" required autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Contraseña:</label>
                <input type="password" id="password" name="password" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn" id="loginBtn">
                <i class="fas fa-sign-in-alt"></i> Iniciar Sesión
            </button>
        </form>

        <div class="security-notice">
            <i class="fas fa-lock"></i> 
            Conexión segura • Solo administradores autorizados
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;
            const loginBtn = document.getElementById('loginBtn');
            const alertContainer = document.getElementById('alertContainer');
            
            loginBtn.disabled = true;
            loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Verificando...';

            try {
                const response = await fetch('/api/auth/admin/login', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ email, password })
                });

                const data = await response.json();

                if (data.success) {
                    // Guardar token en cookie httpOnly a través del servidor
                    document.cookie = \`adminToken=\${data.data.token}; path=/; secure; samesite=strict\`;
                    
                    alertContainer.innerHTML = '<div class="alert success">Acceso autorizado. Redirigiendo...</div>';
                    
                    setTimeout(() => {
                        window.location.href = '/admin/dashboard';
                    }, 1000);
                } else {
                    alertContainer.innerHTML = \`<div class="alert error">\${data.error}</div>\`;
                }
            } catch (error) {
                console.error('Error en login:', error);
                alertContainer.innerHTML = '<div class="alert error">Error de conexión</div>';
            } finally {
                loginBtn.disabled = false;
                loginBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Iniciar Sesión';
            }
        });

        // Limpiar alertas al escribir
        document.getElementById('email').addEventListener('input', () => {
            document.getElementById('alertContainer').innerHTML = '';
        });
        document.getElementById('password').addEventListener('input', () => {
            document.getElementById('alertContainer').innerHTML = '';
        });
    </script>
</body>
</html>
    `);
});

/**
 * POST /admin/logout
 * Cerrar sesión de administrador
 */
router.post('/logout', (req, res) => {
    res.clearCookie('adminToken');
    res.redirect('/admin/login');
});

/**
 * GET /admin/dashboard
 * Panel principal de administración (PROTEGIDO)
 */
router.get('/dashboard', requireAdminAuth, async (req, res) => {
    try {
        const { db } = req.app.locals;
        const stats = await db.getSystemStats();

        res.send(generateDashboardHTML(req.admin, stats));
    } catch (error) {
        console.error('Error cargando dashboard:', error);
        res.status(500).send('Error interno del servidor');
    }
});

/**
 * GET /admin/subscriptions
 * Gestión de suscripciones (PROTEGIDO)
 */
router.get('/subscriptions', requireAdminAuth, async (req, res) => {
    try {
        const { db } = req.app.locals;
        const page = parseInt(req.query.page) || 1;
        const subscriptionsData = await db.getSubscriptions(page, 20);

        res.send(generateSubscriptionsHTML(req.admin, subscriptionsData));
    } catch (error) {
        console.error('Error cargando suscripciones:', error);
        res.status(500).send('Error interno del servidor');
    }
});

/**
 * GET /admin/logs
 * Visualización de logs (PROTEGIDO)
 */
router.get('/logs', requireAdminAuth, async (req, res) => {
    try {
        const { db } = req.app.locals;
        const logs = await db.getMany(
            'SELECT * FROM access_logs ORDER BY created_at DESC LIMIT 100'
        );

        res.send(generateLogsHTML(req.admin, logs));
    } catch (error) {
        console.error('Error cargando logs:', error);
        res.status(500).send('Error interno del servidor');
    }
});

/**
 * Genera HTML para el dashboard
 */
function generateDashboardHTML(admin, stats) {
    return `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Hexzor - Panel Administrativo</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        ${getSharedCSS()}
    </style>
</head>
<body>
    ${getHeaderHTML(admin, 'dashboard')}
    
    <div class="container">
        <h1><i class="fas fa-chart-line"></i> Dashboard</h1>

        <br>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>${stats.subscriptions.total}</h3>
                <p>Total Suscripciones</p>
            </div>
            <div class="stat-card">
                <h3>${stats.subscriptions.active}</h3>
                <p>Suscripciones Activas</p>
            </div>
            <div class="stat-card">
                <h3>${stats.subscriptions.expiringThisWeek}</h3>
                <p>Expiran Esta Semana</p>
            </div>
            <div class="stat-card">
                <h3>${stats.recentActivity.last24Hours.length}</h3>
                <p>Accesos Últimas 24h</p>
            </div>
        </div>

        <div class="recent-activity">
            <h2>Actividad Reciente</h2>

            <br>

            <div class="activity-list">
                ${stats.recentActivity.last24Hours.map(activity => `
                    <div class="activity-item">
                        <span class="activity-email">${activity.email}</span>
                        <span class="activity-count">${activity.access_count} accesos</span>
                    </div>
                `).join('')}
            </div>
        </div>
    </div>
</body>
</html>
    `;
}

/**
 * Genera HTML para gestión de suscripciones
 */
function generateSubscriptionsHTML(admin, subscriptionsData) {
    const { subscriptions, pagination } = subscriptionsData;
    
    return `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Suscripciones - Panel Administrativo</title>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <style>
        ${getSharedCSS()}
    </style>
</head>
<body>
    ${getHeaderHTML(admin, 'subscriptions')}
    
    <div class="container">
        <h1 class="mb"><i class="fas fa-users"></i> Gestión de Suscripciones</h1>

        <div class="subscription-form">
            <h2 class="mb">Agregar Nueva Suscripción</h2>

            <form id="newSubscriptionForm">
                <div class="form-row">
                    <div class="form-group">
                        <label>Email:</label>
                        <input type="email" name="email" required>
                    </div>
                    <div class="form-group">
                        <label>Nombre:</label>
                        <input type="text" name="customerName" required>
                    </div>
                </div>
                <div class="form-row">
                    <div class="form-group">
                        <label>Fecha Inicio:</label>
                        <input type="date" name="startDate" required>
                    </div>
                    <div class="form-group">
                        <label>Fecha Fin:</label>
                        <input type="date" name="endDate" required>
                    </div>
                </div>
                <button type="submit" class="btn mb">Agregar Suscripción</button>
            </form>
        </div>


        <h2 class="mb">Suscripciones Existentes</h2>

        <div class="subscriptions-table">
            <table>
                <thead>
                    <tr>
                        <th>Email</th>
                        <th>Nombre</th>
                        <th>Inicio</th>
                        <th>Fin</th>
                        <th>Estado</th>
                        <th>Acciones</th>
                    </tr>
                </thead>
                <tbody>
                    ${subscriptions.map(sub => `
                        <tr>
                            <td>${sub.email}</td>
                            <td>${sub.customer_name}</td>
                            <td>${new Date(sub.start_date).toLocaleDateString()}</td>
                            <td>${new Date(sub.end_date).toLocaleDateString()}</td>
                            <td><span class="status-${sub.status}">${sub.status}</span></td>
                            <td>
                                <button class="btn expire-btn" data-subscription-id="${sub.id}">Expirar</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    </div>

    <script>
        // JavaScript para manejo de formularios y acciones
        const newSubscriptionForm = document.getElementById('newSubscriptionForm');
        if (newSubscriptionForm) {
            newSubscriptionForm.addEventListener('submit', async (e) => {
                e.preventDefault();

                const form = e.target;
                const submitBtn = form.querySelector('button[type="submit"]');
                let alertContainer = document.getElementById('subscriptionAlert');
                if (!alertContainer) {
                    alertContainer = document.createElement('div');
                    alertContainer.id = 'subscriptionAlert';
                    form.parentNode.insertBefore(alertContainer, form);
                }

                try {
                    submitBtn.disabled = true;
                    submitBtn.textContent = 'Guardando...';

                    const formData = new FormData(form);
                    const payload = {
                        email: formData.get('email'),
                        customerName: formData.get('customerName'),
                        startDate: formData.get('startDate'),
                        endDate: formData.get('endDate'),
                        subscriptionId: formData.get('subscriptionId') || undefined,
                        hotmartTransactionId: formData.get('hotmartTransactionId') || undefined,
                        notes: formData.get('notes') || undefined
                    };

                    // Construir headers y añadir Authorization si existe adminToken en cookies
                    const headers = { 'Content-Type': 'application/json' };
                    const adminToken = (document.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('adminToken='));
                        if (adminToken) {
                            const token = adminToken.split('=')[1];
                            if (token) headers['Authorization'] = 'Bearer ' + token;
                        }

                    const response = await fetch('/api/admin/subscriptions', {
                        method: 'POST',
                        credentials: 'include', // enviar cookies (por si acaso)
                        headers,
                        body: JSON.stringify(payload)
                    });

                    const result = await response.json();

                    if (result && result.success) {
                        alertContainer.innerHTML = '<div class="alert success">' + (result.message || 'Suscripción creada correctamente') + '</div>';
                        form.reset();
                        setTimeout(() => location.reload(), 700);
                    } else {
                        const errMsg = (result && result.error) || 'Error creando suscripción';
                        alertContainer.innerHTML = '<div class="alert error">' + errMsg + '</div>';
                    }

                } catch (error) {
                    console.error('Error enviando nueva suscripción:', error);
                    alertContainer.innerHTML = '<div class="alert error">Error de conexión o interno</div>';
                } finally {
                    submitBtn.disabled = false;
                    submitBtn.textContent = 'Agregar Suscripción';
                }
            });
        }

        // Event listeners para botones de expirar
        document.addEventListener('DOMContentLoaded', function() {
            const expireButtons = document.querySelectorAll('.expire-btn');
            
            expireButtons.forEach(button => {
                button.addEventListener('click', async function() {
                    const subscriptionId = this.getAttribute('data-subscription-id');
                    
                    if (!confirm('¿Estás seguro de expirar esta suscripción?')) {
                        return;
                    }

                    try {
                        const headers = {};
                        const adminToken = (document.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('adminToken='));
                        if (adminToken) {
                            const token = adminToken.split('=')[1];
                            if (token) headers['Authorization'] = 'Bearer ' + token;
                        }

                        const response = await fetch('/api/admin/subscriptions/' + subscriptionId, {
                            method: 'DELETE',
                            credentials: 'include',
                            headers
                        });

                        const result = await response.json();
                        
                        if (result && result.success) {
                            alert('Suscripción expirada correctamente');
                            location.reload();
                        } else {
                            alert(result.error || 'No se pudo expirar la suscripción');
                        }
                    } catch (error) {
                        console.error('Error expiring subscription:', error);
                        alert('Error de conexión al intentar expirar la suscripción');
                    }
                });
            });
        });
    </script>
</body>
</html>
    `;
}

/**
 * Genera CSS compartido
 */
function getSharedCSS() {
    return `
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .header { background: #2762ea; color: white; padding: 1rem 0; margin-bottom: 2rem; }
        .header-content { max-width: 1200px; margin: 0 auto; display: flex; justify-content: space-between; align-items: center; padding: 0 1rem; }
        .nav { display: flex; gap: 1rem; }
        .nav a { color: white; text-decoration: none; padding: 0.5rem 1rem; border-radius: 4px; }
        .nav a.active { background: rgba(255,255,255,0.2); }
        .container { max-width: 1200px; margin: 0 auto; padding: 0 1rem; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
        .stat-card { background: white; padding: 1.5rem; border-radius: 8px; text-align: center; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stat-card h3 { font-size: 2rem; color: #2762ea; margin-bottom: 0.5rem; }
        .btn { background: #2762ea; color: white; border: none; padding: 0.75rem 1.5rem; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #5a67d8; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.25rem; font-weight: 500; }
        .form-group input { width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
        table { width: 100%; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        th, td { padding: 1rem; text-align: left; border-bottom: 1px solid #eee; }
        th { background: #f8f9fa; font-weight: 600; }
        .mb { display: inline-block; margin-bottom: 24px; }
    `;
}

/**
 * Genera header HTML
 */
function getHeaderHTML(admin, currentPage) {
    return `
        <div class="header">
            <div class="header-content">
                <h1><i class="fas fa-cookie-bite"></i> Hexzor Admin</h1>
                <nav class="nav">
                    <a href="/admin/dashboard" ${currentPage === 'dashboard' ? 'class="active"' : ''}>Dashboard</a>
                    <a href="/admin/subscriptions" ${currentPage === 'subscriptions' ? 'class="active"' : ''}>Suscripciones</a>
                    <a href="/admin/logs" ${currentPage === 'logs' ? 'class="active"' : ''}>Logs</a>
                    <form method="POST" action="/admin/logout" style="display: inline;">
                        <button type="submit" style="background: none; border: none; color: white; cursor: pointer; padding: 0.5rem 1rem;">
                            <i class="fas fa-sign-out-alt"></i> Salir
                        </button>
                    </form>
                </nav>
            </div>
        </div>
    `;
}

/**
 * Genera HTML para logs (implementación básica)
 */
function generateLogsHTML(admin, logs) {
    return `
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>Logs - Panel Administrativo</title>
    <style>${getSharedCSS()}</style>
</head>
<body>
    ${getHeaderHTML(admin, 'logs')}
    <div class="container">
        <h1 class="mb">Logs del Sistema</h1>
        <table>
            <thead>
                <tr><th>Fecha</th><th>Email</th><th>Acción</th><th>IP</th><th>Estado</th></tr>
            </thead>
            <tbody>
                ${logs.map(log => `
                    <tr>
                        <td>${new Date(log.created_at).toLocaleString()}</td>
                        <td>${log.email}</td>
                        <td>${log.action}</td>
                        <td>${log.ip_address || 'N/A'}</td>
                        <td>${log.success ? '✅' : '❌'}</td>
                    </tr>
                `).join('')}
            </tbody>
        </table>
    </div>
</body>
</html>
    `;
}

export default router;