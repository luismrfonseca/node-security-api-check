import axios from 'axios';

/**
 * Test Security Headers
 * Checks if important security headers are present
 */
export async function testSecurityHeaders(targetUrl) {
    const results = {
        testName: 'Security Headers Test',
        timestamp: new Date().toISOString(),
        targetUrl: targetUrl,
        presentHeaders: [],
        missingHeaders: [],
        vulnerabilities: [],
        recommendations: [],
        status: 'unknown',
        details: {}
    };

    const securityHeaders = {
        'strict-transport-security': {
            name: 'Strict-Transport-Security (HSTS)',
            description: 'Enforces HTTPS connections',
            severity: 'HIGH',
            recommendation: 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains'
        },
        'content-security-policy': {
            name: 'Content-Security-Policy (CSP)',
            description: 'Prevents XSS and other injection attacks',
            severity: 'HIGH',
            recommendation: 'Add CSP header with appropriate directives for your application'
        },
        'x-content-type-options': {
            name: 'X-Content-Type-Options',
            description: 'Prevents MIME type sniffing',
            severity: 'MEDIUM',
            recommendation: 'Add: X-Content-Type-Options: nosniff'
        },
        'x-frame-options': {
            name: 'X-Frame-Options',
            description: 'Prevents clickjacking attacks',
            severity: 'MEDIUM',
            recommendation: 'Add: X-Frame-Options: DENY or SAMEORIGIN'
        },
        'x-xss-protection': {
            name: 'X-XSS-Protection',
            description: 'Enables browser XSS filtering',
            severity: 'LOW',
            recommendation: 'Add: X-XSS-Protection: 1; mode=block'
        },
        'referrer-policy': {
            name: 'Referrer-Policy',
            description: 'Controls referrer information',
            severity: 'LOW',
            recommendation: 'Add: Referrer-Policy: no-referrer or strict-origin-when-cross-origin'
        },
        'permissions-policy': {
            name: 'Permissions-Policy',
            description: 'Controls browser features and APIs',
            severity: 'MEDIUM',
            recommendation: 'Add Permissions-Policy header to control feature access'
        }
    };

    try {
        const response = await axios.get(targetUrl, {
            timeout: 5000,
            validateStatus: () => true
        });

        // Check each security header
        for (const [headerKey, headerInfo] of Object.entries(securityHeaders)) {
            const headerValue = response.headers[headerKey];

            if (headerValue) {
                results.presentHeaders.push(headerInfo.name);
                results.details[headerInfo.name] = {
                    present: true,
                    value: headerValue,
                    status: 'OK'
                };
            } else {
                results.missingHeaders.push(headerInfo.name);
                results.details[headerInfo.name] = {
                    present: false,
                    severity: headerInfo.severity,
                    recommendation: headerInfo.recommendation
                };

                results.vulnerabilities.push({
                    severity: headerInfo.severity,
                    description: `Missing ${headerInfo.name}`,
                    details: headerInfo.description
                });
            }
        }

        // Additional header checks
        const serverHeader = response.headers['server'];
        if (serverHeader) {
            results.details['Server Header'] = {
                present: true,
                value: serverHeader,
                warning: 'Server header exposes server information',
                recommendation: 'Consider removing or obfuscating the Server header'
            };
        }

        const poweredByHeader = response.headers['x-powered-by'];
        if (poweredByHeader) {
            results.details['X-Powered-By Header'] = {
                present: true,
                value: poweredByHeader,
                warning: 'X-Powered-By header exposes technology stack',
                recommendation: 'Remove X-Powered-By header to avoid information disclosure'
            };

            results.vulnerabilities.push({
                severity: 'LOW',
                description: 'Information disclosure via X-Powered-By header',
                details: `Exposes: ${poweredByHeader}`
            });
        }

        // Analysis
        const criticalMissing = results.vulnerabilities.filter(v => v.severity === 'HIGH').length;
        const mediumMissing = results.vulnerabilities.filter(v => v.severity === 'MEDIUM').length;

        if (criticalMissing > 0) {
            results.status = 'vulnerable';
            results.recommendations.push(`URGENT: ${criticalMissing} critical security headers are missing`);
        } else if (mediumMissing > 0) {
            results.status = 'weak';
            results.recommendations.push(`${mediumMissing} important security headers are missing`);
        } else if (results.missingHeaders.length > 0) {
            results.status = 'good';
            results.recommendations.push('Consider adding remaining security headers for defense in depth');
        } else {
            results.status = 'excellent';
            results.recommendations.push('All major security headers are present');
        }

        results.recommendations.push('Use security header testing tools regularly');
        results.recommendations.push('Review and update security headers as standards evolve');

    } catch (error) {
        results.error = error.message;
        results.status = 'error';
    }

    return results;
}
