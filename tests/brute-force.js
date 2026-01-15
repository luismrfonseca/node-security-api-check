import axios from 'axios';

/**
 * Test Brute Force Protection
 * Attempts multiple login requests to check if the API has brute force protection
 */
export async function testBruteForce(targetUrl, endpoint, usernameField = 'username', passwordField = 'password', attempts = 50) {
    const results = {
        testName: 'Brute Force Protection Test',
        timestamp: new Date().toISOString(),
        targetUrl: `${targetUrl}${endpoint}`,
        totalAttempts: attempts,
        successfulAttempts: 0,
        blockedAttempts: 0,
        averageResponseTime: 0,
        vulnerabilities: [],
        recommendations: [],
        status: 'unknown',
        details: []
    };

    const commonPasswords = [
        'password', '123456', '12345678', 'qwerty', 'abc123',
        'monkey', '1234567', 'letmein', 'trustno1', 'dragon',
        'baseball', 'iloveyou', 'master', 'sunshine', 'ashley',
        'bailey', 'passw0rd', 'shadow', '123123', '654321'
    ];

    const responseTimes = [];
    let blockedCount = 0;
    let successCount = 0;

    try {
        for (let i = 0; i < attempts; i++) {
            const startTime = Date.now();
            const password = commonPasswords[i % commonPasswords.length];

            try {
                const response = await axios.post(`${targetUrl}${endpoint}`, {
                    [usernameField]: 'testuser',
                    [passwordField]: password
                }, {
                    timeout: 5000,
                    validateStatus: () => true // Accept any status code
                });

                const responseTime = Date.now() - startTime;
                responseTimes.push(responseTime);

                results.details.push({
                    attempt: i + 1,
                    password: password,
                    statusCode: response.status,
                    responseTime: responseTime,
                    blocked: response.status === 429 || response.status === 403
                });

                if (response.status === 429 || response.status === 403) {
                    blockedCount++;
                } else if (response.status === 200) {
                    successCount++;
                }

                // Small delay to avoid overwhelming the server
                await new Promise(resolve => setTimeout(resolve, 100));
            } catch (error) {
                results.details.push({
                    attempt: i + 1,
                    password: password,
                    error: error.message,
                    responseTime: Date.now() - startTime
                });
            }
        }

        results.successfulAttempts = successCount;
        results.blockedAttempts = blockedCount;
        results.averageResponseTime = responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length;

        // Analysis
        if (blockedCount === 0) {
            results.status = 'vulnerable';
            results.vulnerabilities.push({
                severity: 'HIGH',
                description: 'No brute force protection detected',
                details: `All ${attempts} attempts were processed without any blocking mechanism`
            });
            results.recommendations.push('Implement rate limiting on authentication endpoints');
            results.recommendations.push('Add account lockout after multiple failed attempts');
            results.recommendations.push('Implement CAPTCHA after several failed login attempts');
        } else if (blockedCount < attempts * 0.3) {
            results.status = 'weak';
            results.vulnerabilities.push({
                severity: 'MEDIUM',
                description: 'Weak brute force protection',
                details: `Only ${blockedCount} out of ${attempts} attempts were blocked`
            });
            results.recommendations.push('Strengthen rate limiting rules');
            results.recommendations.push('Reduce the threshold for account lockout');
        } else {
            results.status = 'protected';
            results.recommendations.push('Brute force protection is working well');
            results.recommendations.push('Consider adding additional layers like CAPTCHA for enhanced security');
        }

    } catch (error) {
        results.error = error.message;
        results.status = 'error';
    }

    return results;
}
