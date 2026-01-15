import axios from 'axios';

/**
 * Test Authentication Security
 * Tests various authentication vulnerabilities
 */
export async function testAuthentication(targetUrl, endpoint, credentials = {}) {
    const results = {
        testName: 'Authentication Security Test',
        timestamp: new Date().toISOString(),
        targetUrl: `${targetUrl}${endpoint}`,
        vulnerabilities: [],
        recommendations: [],
        status: 'unknown',
        details: {}
    };

    try {
        // Test 1: Empty credentials
        try {
            const response = await axios.post(`${targetUrl}${endpoint}`, {}, {
                timeout: 5000,
                validateStatus: () => true
            });

            results.details.emptyCredentials = {
                statusCode: response.status,
                accepted: response.status === 200
            };

            if (response.status === 200) {
                results.vulnerabilities.push({
                    severity: 'CRITICAL',
                    description: 'Empty credentials accepted',
                    details: 'Authentication endpoint accepts requests with no credentials'
                });
            }
        } catch (error) {
            results.details.emptyCredentials = { error: error.message };
        }

        // Test 2: Weak passwords
        const weakPasswords = ['123456', 'password', 'admin', '12345678', 'qwerty'];

        for (const weakPass of weakPasswords) {
            try {
                const response = await axios.post(`${targetUrl}${endpoint}`, {
                    username: 'admin',
                    password: weakPass
                }, {
                    timeout: 5000,
                    validateStatus: () => true
                });

                if (response.status === 200) {
                    results.vulnerabilities.push({
                        severity: 'CRITICAL',
                        description: 'Weak password accepted',
                        details: `Weak password "${weakPass}" was accepted`
                    });
                    break;
                }
            } catch (error) {
                // Expected
            }

            await new Promise(resolve => setTimeout(resolve, 100));
        }

        // Test 3: Case sensitivity
        if (credentials.username && credentials.password) {
            try {
                const response1 = await axios.post(`${targetUrl}${endpoint}`, {
                    username: credentials.username.toUpperCase(),
                    password: credentials.password
                }, {
                    timeout: 5000,
                    validateStatus: () => true
                });

                const response2 = await axios.post(`${targetUrl}${endpoint}`, {
                    username: credentials.username.toLowerCase(),
                    password: credentials.password
                }, {
                    timeout: 5000,
                    validateStatus: () => true
                });

                results.details.caseSensitivity = {
                    uppercase: response1.status,
                    lowercase: response2.status,
                    bothAccepted: response1.status === 200 && response2.status === 200
                };

                if (response1.status === 200 && response2.status === 200) {
                    results.vulnerabilities.push({
                        severity: 'MEDIUM',
                        description: 'Username is not case-sensitive',
                        details: 'This could facilitate brute force attacks'
                    });
                }
            } catch (error) {
                results.details.caseSensitivity = { error: error.message };
            }
        }

        // Test 4: Response timing (timing attack vulnerability)
        const timingTests = [];

        for (let i = 0; i < 5; i++) {
            const startTime = Date.now();

            try {
                await axios.post(`${targetUrl}${endpoint}`, {
                    username: 'nonexistentuser' + i,
                    password: 'wrongpassword'
                }, {
                    timeout: 5000,
                    validateStatus: () => true
                });

                timingTests.push(Date.now() - startTime);
            } catch (error) {
                timingTests.push(Date.now() - startTime);
            }

            await new Promise(resolve => setTimeout(resolve, 100));
        }

        const avgTime = timingTests.reduce((a, b) => a + b, 0) / timingTests.length;
        const variance = timingTests.reduce((sum, time) => sum + Math.pow(time - avgTime, 2), 0) / timingTests.length;
        const stdDev = Math.sqrt(variance);

        results.details.timingAnalysis = {
            averageResponseTime: `${avgTime.toFixed(2)}ms`,
            standardDeviation: `${stdDev.toFixed(2)}ms`,
            samples: timingTests
        };

        if (stdDev > avgTime * 0.3) {
            results.vulnerabilities.push({
                severity: 'MEDIUM',
                description: 'Possible timing attack vulnerability',
                details: 'Response times vary significantly, which could leak information about valid usernames'
            });
        }

        // Test 5: Information disclosure in error messages
        try {
            const response = await axios.post(`${targetUrl}${endpoint}`, {
                username: 'testuser',
                password: 'wrongpassword'
            }, {
                timeout: 5000,
                validateStatus: () => true
            });

            const responseText = JSON.stringify(response.data).toLowerCase();

            if (responseText.includes('user not found') || responseText.includes('invalid username')) {
                results.vulnerabilities.push({
                    severity: 'MEDIUM',
                    description: 'Information disclosure in error messages',
                    details: 'Error messages reveal whether username exists'
                });
            }

            results.details.errorMessage = {
                statusCode: response.status,
                message: response.data
            };
        } catch (error) {
            results.details.errorMessage = { error: error.message };
        }

        // Test 6: Check for HTTPS
        if (targetUrl.startsWith('http://')) {
            results.vulnerabilities.push({
                severity: 'CRITICAL',
                description: 'Authentication over HTTP',
                details: 'Credentials are transmitted in plain text without encryption'
            });
            results.recommendations.push('URGENT: Use HTTPS for all authentication endpoints');
        }

        // Analysis
        const criticalVulns = results.vulnerabilities.filter(v => v.severity === 'CRITICAL').length;
        const highVulns = results.vulnerabilities.filter(v => v.severity === 'HIGH').length;

        if (criticalVulns > 0) {
            results.status = 'vulnerable';
            results.recommendations.push('URGENT: Critical authentication vulnerabilities detected');
        } else if (highVulns > 0) {
            results.status = 'weak';
            results.recommendations.push('Important authentication security issues found');
        } else if (results.vulnerabilities.length > 0) {
            results.status = 'good';
            results.recommendations.push('Minor authentication improvements recommended');
        } else {
            results.status = 'secure';
            results.recommendations.push('Authentication appears to be secure');
        }

        results.recommendations.push('Implement strong password policies');
        results.recommendations.push('Use constant-time comparison for credentials');
        results.recommendations.push('Implement account lockout after failed attempts');
        results.recommendations.push('Use generic error messages that don\'t reveal user existence');
        results.recommendations.push('Implement multi-factor authentication (MFA)');

    } catch (error) {
        results.error = error.message;
        results.status = 'error';
    }

    return results;
}
