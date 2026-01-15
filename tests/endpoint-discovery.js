import axios from 'axios';

/**
 * Endpoint Discovery
 * Discovers common API endpoints that might be exposed
 */
export async function discoverEndpoints(targetUrl, commonPaths = []) {
    const results = {
        testName: 'Endpoint Discovery Test',
        timestamp: new Date().toISOString(),
        targetUrl: targetUrl,
        totalPaths: 0,
        foundEndpoints: [],
        vulnerabilities: [],
        recommendations: [],
        status: 'unknown',
        details: []
    };

    // Common API endpoints to test
    const defaultPaths = [
        '/api',
        '/api/v1',
        '/api/v2',
        '/admin',
        '/admin/login',
        '/dashboard',
        '/users',
        '/api/users',
        '/api/admin',
        '/debug',
        '/test',
        '/dev',
        '/swagger',
        '/api-docs',
        '/docs',
        '/graphql',
        '/health',
        '/status',
        '/metrics',
        '/config',
        '/env',
        '/.env',
        '/backup',
        '/db',
        '/database',
        '/phpmyadmin',
        '/adminer',
        '/console',
        '/api/keys',
        '/api/tokens',
        '/api/config'
    ];

    const pathsToTest = commonPaths.length > 0 ? commonPaths : defaultPaths;
    results.totalPaths = pathsToTest.length;

    try {
        for (const path of pathsToTest) {
            try {
                const fullUrl = `${targetUrl}${path}`;
                const response = await axios.get(fullUrl, {
                    timeout: 3000,
                    validateStatus: () => true,
                    maxRedirects: 0
                });

                const detail = {
                    path: path,
                    statusCode: response.status,
                    found: response.status < 400,
                    size: JSON.stringify(response.data).length
                };

                if (response.status < 400) {
                    results.foundEndpoints.push(path);

                    // Check for sensitive endpoints
                    if (path.includes('admin') || path.includes('debug') || path.includes('config')) {
                        results.vulnerabilities.push({
                            severity: 'HIGH',
                            description: `Sensitive endpoint exposed: ${path}`,
                            details: `Status: ${response.status}`
                        });
                    }

                    if (path.includes('.env') || path.includes('backup') || path.includes('db')) {
                        results.vulnerabilities.push({
                            severity: 'CRITICAL',
                            description: `Critical endpoint exposed: ${path}`,
                            details: 'This endpoint may expose sensitive configuration or data'
                        });
                    }

                    if (path.includes('swagger') || path.includes('api-docs') || path.includes('docs')) {
                        detail.note = 'API documentation endpoint found';
                    }

                    if (path.includes('graphql')) {
                        detail.note = 'GraphQL endpoint found - check for introspection';
                    }
                }

                results.details.push(detail);

            } catch (error) {
                results.details.push({
                    path: path,
                    error: error.code || error.message,
                    found: false
                });
            }

            // Small delay between requests
            await new Promise(resolve => setTimeout(resolve, 50));
        }

        // Analysis
        if (results.vulnerabilities.some(v => v.severity === 'CRITICAL')) {
            results.status = 'vulnerable';
            results.recommendations.push('URGENT: Critical endpoints are publicly accessible');
            results.recommendations.push('Restrict access to sensitive endpoints immediately');
        } else if (results.vulnerabilities.length > 0) {
            results.status = 'weak';
            results.recommendations.push('Some sensitive endpoints are exposed');
            results.recommendations.push('Implement proper access controls');
        } else if (results.foundEndpoints.length > 5) {
            results.status = 'exposed';
            results.recommendations.push('Many endpoints are discoverable');
            results.recommendations.push('Consider implementing endpoint authentication');
        } else {
            results.status = 'protected';
            results.recommendations.push('Endpoint exposure is minimal');
        }

        results.recommendations.push('Use authentication for all sensitive endpoints');
        results.recommendations.push('Disable debug/development endpoints in production');
        results.recommendations.push('Implement rate limiting on discovery attempts');
        results.recommendations.push('Monitor for endpoint scanning attempts');

    } catch (error) {
        results.error = error.message;
        results.status = 'error';
    }

    return results;
}
