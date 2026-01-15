import axios from 'axios';

/**
 * Test CORS Configuration
 * Checks if CORS is properly configured
 */
export async function testCORS(targetUrl) {
    const results = {
        testName: 'CORS Configuration Test',
        timestamp: new Date().toISOString(),
        targetUrl: targetUrl,
        corsEnabled: false,
        allowedOrigins: [],
        allowedMethods: [],
        allowedHeaders: [],
        allowsCredentials: false,
        vulnerabilities: [],
        recommendations: [],
        status: 'unknown',
        details: {}
    };

    const testOrigins = [
        'http://evil.com',
        'https://malicious.example.com',
        'null',
        '*'
    ];

    try {
        // Test with different origins
        for (const origin of testOrigins) {
            try {
                const response = await axios.options(targetUrl, {
                    headers: {
                        'Origin': origin,
                        'Access-Control-Request-Method': 'POST',
                        'Access-Control-Request-Headers': 'Content-Type'
                    },
                    timeout: 5000,
                    validateStatus: () => true
                });

                const corsHeaders = {
                    allowOrigin: response.headers['access-control-allow-origin'],
                    allowMethods: response.headers['access-control-allow-methods'],
                    allowHeaders: response.headers['access-control-allow-headers'],
                    allowCredentials: response.headers['access-control-allow-credentials'],
                    maxAge: response.headers['access-control-max-age']
                };

                results.details[`Origin: ${origin}`] = {
                    statusCode: response.status,
                    headers: corsHeaders,
                    accepted: !!corsHeaders.allowOrigin
                };

                if (corsHeaders.allowOrigin) {
                    results.corsEnabled = true;

                    if (!results.allowedOrigins.includes(corsHeaders.allowOrigin)) {
                        results.allowedOrigins.push(corsHeaders.allowOrigin);
                    }

                    if (corsHeaders.allowOrigin === '*') {
                        results.vulnerabilities.push({
                            severity: 'HIGH',
                            description: 'Wildcard (*) CORS origin allowed',
                            details: 'Access-Control-Allow-Origin: * allows any domain to make requests'
                        });
                    }

                    if (corsHeaders.allowOrigin === 'null') {
                        results.vulnerabilities.push({
                            severity: 'MEDIUM',
                            description: 'Null origin allowed',
                            details: 'Allowing null origin can be exploited by sandboxed iframes'
                        });
                    }

                    if (corsHeaders.allowOrigin === origin && origin.includes('evil')) {
                        results.vulnerabilities.push({
                            severity: 'HIGH',
                            description: 'Untrusted origin accepted',
                            details: `The API accepted requests from untrusted origin: ${origin}`
                        });
                    }

                    if (corsHeaders.allowCredentials === 'true') {
                        results.allowsCredentials = true;

                        if (corsHeaders.allowOrigin === '*') {
                            results.vulnerabilities.push({
                                severity: 'CRITICAL',
                                description: 'Credentials allowed with wildcard origin',
                                details: 'This combination is dangerous and not allowed by browsers'
                            });
                        }
                    }

                    if (corsHeaders.allowMethods) {
                        results.allowedMethods = corsHeaders.allowMethods.split(',').map(m => m.trim());
                    }

                    if (corsHeaders.allowHeaders) {
                        results.allowedHeaders = corsHeaders.allowHeaders.split(',').map(h => h.trim());
                    }
                }

            } catch (error) {
                results.details[`Origin: ${origin}`] = {
                    error: error.message
                };
            }

            await new Promise(resolve => setTimeout(resolve, 100));
        }

        // Analysis
        if (!results.corsEnabled) {
            results.status = 'protected';
            results.recommendations.push('CORS is not enabled or is very restrictive');
            results.recommendations.push('If you need CORS, enable it only for trusted origins');
        } else if (results.vulnerabilities.some(v => v.severity === 'CRITICAL' || v.severity === 'HIGH')) {
            results.status = 'vulnerable';
            results.recommendations.push('URGENT: Fix critical CORS misconfigurations');
            results.recommendations.push('Never use Access-Control-Allow-Origin: * with credentials');
            results.recommendations.push('Whitelist only specific trusted domains');
            results.recommendations.push('Avoid reflecting the Origin header without validation');
        } else if (results.vulnerabilities.length > 0) {
            results.status = 'weak';
            results.recommendations.push('CORS is enabled but has some security concerns');
            results.recommendations.push('Review and restrict allowed origins');
        } else {
            results.status = 'good';
            results.recommendations.push('CORS configuration appears secure');
            results.recommendations.push('Regularly review allowed origins');
        }

        results.recommendations.push('Use CORS only when necessary');
        results.recommendations.push('Implement additional authentication for sensitive endpoints');

    } catch (error) {
        results.error = error.message;
        results.status = 'error';
    }

    return results;
}
