import axios from 'axios';

export async function testTimingAttacks(targetUrl, endpoint, samples = 20) {
    const results = {
        testName: 'Timing Attack Test',
        timestamp: new Date().toISOString(),
        targetUrl: `${targetUrl}${endpoint}`,
        samples: samples,
        vulnerabilities: [],
        recommendations: [],
        status: 'unknown',
        details: {}
    };

    const timings = [];

    try {
        for (let i = 0; i < samples; i++) {
            const start = Date.now();

            try {
                await axios.post(`${targetUrl}${endpoint}`, {
                    username: 'user' + i,
                    password: 'pass' + i
                }, {
                    timeout: 5000,
                    validateStatus: () => true
                });

                timings.push(Date.now() - start);
            } catch (error) {
                timings.push(Date.now() - start);
            }

            await new Promise(resolve => setTimeout(resolve, 100));
        }

        const avg = timings.reduce((a, b) => a + b, 0) / timings.length;
        const variance = timings.reduce((sum, t) => sum + Math.pow(t - avg, 2), 0) / timings.length;
        const stdDev = Math.sqrt(variance);

        results.details = {
            averageTime: `${avg.toFixed(2)}ms`,
            standardDeviation: `${stdDev.toFixed(2)}ms`,
            timings: timings
        };

        if (stdDev > avg * 0.3) {
            results.vulnerabilities.push({
                severity: 'MEDIUM',
                description: 'Timing attack vulnerability',
                details: 'Response times vary significantly'
            });
            results.status = 'vulnerable';
        } else {
            results.status = 'protected';
        }

        results.recommendations.push('Use constant-time comparison');

    } catch (error) {
        results.error = error.message;
        results.status = 'error';
    }

    return results;
}
