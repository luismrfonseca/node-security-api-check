import jwt from 'jsonwebtoken';

/**
 * Test JWT Token Security
 * Analyzes JWT tokens for common vulnerabilities
 */
export async function testJWT(token) {
    const results = {
        testName: 'JWT Token Security Test',
        timestamp: new Date().toISOString(),
        tokenProvided: !!token,
        vulnerabilities: [],
        recommendations: [],
        status: 'unknown',
        details: {}
    };

    if (!token) {
        results.status = 'error';
        results.error = 'No token provided';
        return results;
    }

    try {
        // Decode without verification
        const decoded = jwt.decode(token, { complete: true });

        if (!decoded) {
            results.status = 'error';
            results.error = 'Invalid JWT token format';
            return results;
        }

        results.details.header = decoded.header;
        results.details.payload = decoded.payload;

        // Check algorithm
        const algorithm = decoded.header.alg;
        results.details.algorithm = algorithm;

        if (algorithm === 'none') {
            results.vulnerabilities.push({
                severity: 'CRITICAL',
                description: 'Algorithm set to "none"',
                details: 'Token can be forged without a signature'
            });
        }

        if (algorithm.startsWith('HS')) {
            results.details.algorithmType = 'Symmetric (HMAC)';
            results.recommendations.push('Using symmetric algorithm - ensure secret is strong and secure');
        } else if (algorithm.startsWith('RS') || algorithm.startsWith('ES')) {
            results.details.algorithmType = 'Asymmetric (RSA/ECDSA)';
            results.recommendations.push('Using asymmetric algorithm - good for distributed systems');
        }

        // Check expiration
        if (decoded.payload.exp) {
            const expirationDate = new Date(decoded.payload.exp * 1000);
            const now = new Date();
            const timeUntilExpiry = expirationDate - now;

            results.details.expiration = {
                timestamp: decoded.payload.exp,
                date: expirationDate.toISOString(),
                expired: timeUntilExpiry < 0,
                timeRemaining: timeUntilExpiry > 0 ? `${Math.floor(timeUntilExpiry / 1000 / 60)} minutes` : 'Expired'
            };

            if (timeUntilExpiry < 0) {
                results.vulnerabilities.push({
                    severity: 'LOW',
                    description: 'Token is expired',
                    details: `Expired on ${expirationDate.toISOString()}`
                });
            }

            // Check if expiration is too long
            const maxReasonableExpiry = 24 * 60 * 60 * 1000; // 24 hours
            if (timeUntilExpiry > maxReasonableExpiry) {
                results.vulnerabilities.push({
                    severity: 'MEDIUM',
                    description: 'Token expiration time is too long',
                    details: 'Long-lived tokens increase security risk if compromised'
                });
            }
        } else {
            results.vulnerabilities.push({
                severity: 'HIGH',
                description: 'No expiration claim (exp)',
                details: 'Token never expires, which is a security risk'
            });
            results.recommendations.push('Always set an expiration time for JWT tokens');
        }

        // Check for sensitive data in payload
        const sensitiveFields = ['password', 'secret', 'apiKey', 'api_key', 'privateKey', 'private_key'];
        const payloadKeys = Object.keys(decoded.payload);

        for (const field of sensitiveFields) {
            if (payloadKeys.some(key => key.toLowerCase().includes(field.toLowerCase()))) {
                results.vulnerabilities.push({
                    severity: 'CRITICAL',
                    description: 'Sensitive data in JWT payload',
                    details: `Possible sensitive field detected: ${field}`
                });
            }
        }

        // Check for standard claims
        const standardClaims = ['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti'];
        results.details.standardClaims = {};

        for (const claim of standardClaims) {
            if (decoded.payload[claim]) {
                results.details.standardClaims[claim] = decoded.payload[claim];
            }
        }

        // Try to verify with common weak secrets
        const weakSecrets = ['secret', 'password', '123456', 'admin', 'test', 'jwt-secret'];

        for (const secret of weakSecrets) {
            try {
                jwt.verify(token, secret);
                results.vulnerabilities.push({
                    severity: 'CRITICAL',
                    description: 'Weak JWT secret detected',
                    details: `Token can be verified with weak secret: "${secret}"`
                });
                break;
            } catch (err) {
                // Expected - secret doesn't match
            }
        }

        // Analysis
        const criticalVulns = results.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
        const highVulns = results.vulnerabilities.filter(v => v.severity === 'HIGH').length;

        if (criticalVulns > 0) {
            results.status = 'vulnerable';
            results.recommendations.push('URGENT: Critical JWT vulnerabilities detected');
        } else if (highVulns > 0) {
            results.status = 'weak';
            results.recommendations.push('Important JWT security issues found');
        } else if (results.vulnerabilities.length > 0) {
            results.status = 'good';
            results.recommendations.push('Minor JWT security improvements recommended');
        } else {
            results.status = 'secure';
            results.recommendations.push('JWT token appears to be secure');
        }

        results.recommendations.push('Use strong, randomly generated secrets');
        results.recommendations.push('Set appropriate expiration times');
        results.recommendations.push('Never store sensitive data in JWT payload');
        results.recommendations.push('Implement token refresh mechanism');

    } catch (error) {
        results.error = error.message;
        results.status = 'error';
    }

    return results;
}
