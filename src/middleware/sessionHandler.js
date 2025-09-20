/**
 * Middleware global para manejar cookies expiradas en todas las rutas de admin panel
 */
export const handleExpiredSessions = (req, res, next) => {
    // Solo aplicar a rutas del panel de admin (no API)
    if (req.path.startsWith('/admin') && req.path !== '/admin/login') {
        const token = req.cookies?.adminToken;
        
        if (!token) {
            res.clearCookie('adminToken');
            return res.redirect('/admin/login');
        }
        
        try {
            // Verificación rápida del token sin validar completamente
            const jwt = require('jsonwebtoken');
            jwt.verify(token, process.env.JWT_SECRET);
        } catch (error) {
            // Token expirado o inválido
            res.clearCookie('adminToken', {
                path: '/',
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict'
            });
            return res.redirect('/admin/login');
        }
    }
    
    next();
};