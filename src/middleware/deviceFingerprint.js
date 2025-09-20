import crypto from 'crypto';

/**
 * Genera fingerprint único del dispositivo basado en headers
 */
export const generateDeviceFingerprint = (req) => {
    const components = [
        req.headers['user-agent'] || '',
        req.headers['accept-language'] || '',
        req.headers['accept-encoding'] || '',
        req.ip || '',
        req.headers['x-forwarded-for'] || ''
    ].join('|');
    
    return crypto.createHash('sha256').update(components).digest('hex').substring(0, 16);
};

/**
 * Middleware para capturar fingerprint del dispositivo
 */
export const captureDeviceFingerprint = (req, res, next) => {
    req.deviceFingerprint = generateDeviceFingerprint(req);
    next();
};