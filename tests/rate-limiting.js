import axios from 'axios';

/**
 * Test Rate Limiting
 * Sends multiple requests in a short time to check if rate limiting is implemented
 */
export async function testRateLimiting(targetUrl, endpoint, requestCount = 100, timeWindow = 1000) {
    const results = {
        testName: 'Rate Limiting Test',
        timestamp: new Date().toISOString(),
        targetUrl: `${targetUrl}${endpoint}`,
        totalRequests: requestCount,
        timeWindow: `${timeWindow}ms`,
        successfulRequests: 0,
        rateLimitedRequests: 0,
        averageResponseTime: 0,
        vulnerabilities: [],
        recommendations: [],
        status: 'unknown',
        details: []
    };

    const responseTimes = [];
    let rateLimitedCount = 0;
    let successCount = 0;

    try {
        const startTime = Date.now();
        const promises = [];

        // Send all requests simultaneously
        for (let i = 0; i < requestCount; i++) {
            const promise = (async () => {
                const reqStartTime = Date.now();
                try {
                    const response = await axios.get(`${targetUrl}${endpoint}`, {
                        timeout: 5000,
                        validateStatus: () => true
                    });

                    const responseTime = Date.now() - reqStartTime;
                    responseTimes.push(responseTime);

                    const detail = {
                        request: i + 1,
                        statusCode: response.status,
                        responseTime: responseTime,
                        rateLimited: response.status === 429
                    };

                    if (response.headers['x-ratelimit-limit']) {
                        detail.rateLimit = {
                            limit: response.headers['x-ratelimit-limit'],
                            remaining: response.headers['x-ratelimit-remaining'],
                            reset: response.headers['x-ratelimit-reset']
                        };
                    }

                    results.details.push(detail);

                    if (response.status === 429) {
                        rateLimitedCount++;
                    } else if (response.status === 200) {
                        successCount++;
                    }
                } catch (error) {
                    results.details.push({
                        request: i + 1,
                        error: error.message,
                        responseTime: Date.now() - reqStartTime
                    });
                }
            })();

            promises.push(promise);
        }

        await Promise.all(promises);

        const totalTime = Date.now() - startTime;

        results.successfulRequests = successCount;
        results.rateLimitedRequests = rateLimitedCount;
        results.averageResponseTime = responseTimes.length > 0
            ? responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length
            : 0;
        results.totalExecutionTime = `${totalTime}ms`;

        // Analysis
        if (rateLimitedCount === 0) {
            results.status = 'vulnerable';
            results.vulnerabilities.push({
                severity: 'HIGH',
                description: 'No rate limiting detected',
                details: `${requestCount} requests were processed in ${totalTime}ms without any rate limiting`
            });
            results.recommendations.push('Implement rate limiting to prevent API abuse');
            results.recommendations.push('Consider using a rate limiting middleware like express-rate-limit');
            results.recommendations.push('Set appropriate limits based on your API usage patterns');
        } else if (rateLimitedCount < requestCount * 0.5) {
            results.status = 'weak';
            results.vulnerabilities.push({
                severity: 'MEDIUM',
                description: 'Weak rate limiting',
                details: `Only ${rateLimitedCount} out of ${requestCount} requests were rate limited`
            });
            results.recommendations.push('Strengthen rate limiting rules');
            results.recommendations.push('Reduce the request threshold or time window');
        } else {
            results.status = 'protected';
            results.recommendations.push('Rate limiting is working effectively');
            results.recommendations.push('Monitor rate limit metrics to adjust thresholds as needed');
        }

    } catch (error) {
        results.error = error.message;
        results.status = 'error';
    }

    return results;
}
