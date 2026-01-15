import axios from 'axios';

/**
 * Test XSS (Cross-Site Scripting) Vulnerabilities
 * Tests if the API properly sanitizes input and output
 */
export async function testXSS(targetUrl, endpoint, parameters = []) {
    const results = {
        testName: 'XSS (Cross-Site Scripting) Test',
        timestamp: new Date().toISOString(),
        targetUrl: `${targetUrl}${endpoint}`,
        totalTests: 0,
        vulnerableParameters: [],
        vulnerabilities: [],
        recommendations: [],
        status: 'unknown',
        details: []
    };

    // Common XSS payloads
    const xssPayloads = [
        '<script>alert("XSS")</script>',
        '<img src=x onerror=alert("XSS")>',
        '<svg/onload=alert("XSS")>',
        '<iframe src="javascript:alert(\'XSS\')">',
        '<body onload=alert("XSS")>',
        '<input onfocus=alert("XSS") autofocus>',
        '<select onfocus=alert("XSS") autofocus>',
        '<textarea onfocus=alert("XSS") autofocus>',
        '<marquee onstart=alert("XSS")>',
        '<div onmouseover=alert("XSS")>',
        '"><script>alert(String.fromCharCode(88,83,83))</script>',
        '\'><script>alert(String.fromCharCode(88,83,83))</script>',
        '<IMG SRC="javascript:alert(\'XSS\');">',
        '<IMG SRC=JaVaScRiPt:alert(\'XSS\')>',
        '<IMG SRC=`javascript:alert("XSS")`>',
        '<SCRIPT SRC=http://xss.rocks/xss.js></SCRIPT>',
        '<<SCRIPT>alert("XSS");//<</SCRIPT>',
        '<SCRIPT>alert(String.fromCharCode(88,83,83))</SCRIPT>',
        '<IMG """><SCRIPT>alert("XSS")</SCRIPT>">',
        'javascript:alert("XSS")'
    ];

    try {
        if (parameters.length === 0) {
            parameters = ['name', 'comment', 'message', 'description', 'title', 'content'];
        }

        for (const param of parameters) {
            for (const payload of xssPayloads) {
                results.totalTests++;

                try {
                    // Test as POST data
                    const response = await axios.post(`${targetUrl}${endpoint}`, {
                        [param]: payload
                    }, {
                        timeout: 5000,
                        validateStatus: () => true
                    });

                    const responseText = typeof response.data === 'string'
                        ? response.data
                        : JSON.stringify(response.data);

                    // Check if payload is reflected in response without encoding
                    const isReflected = responseText.includes(payload);
                    const isEncoded = responseText.includes(payload.replace(/</g, '&lt;').replace(/>/g, '&gt;'));

                    const detail = {
                        parameter: param,
                        payload: payload.substring(0, 50) + (payload.length > 50 ? '...' : ''),
                        statusCode: response.status,
                        isReflected: isReflected,
                        isProperlyEncoded: isEncoded && !isReflected
                    };

                    if (isReflected && !isEncoded) {
                        detail.vulnerability = 'Unencoded payload reflected in response';
                        results.vulnerableParameters.push(param);
                    }

                    results.details.push(detail);

                } catch (error) {
                    results.details.push({
                        parameter: param,
                        payload: payload.substring(0, 50) + (payload.length > 50 ? '...' : ''),
                        error: error.message
                    });
                }

                await new Promise(resolve => setTimeout(resolve, 50));
            }
        }

        // Analysis
        const uniqueVulnerableParams = [...new Set(results.vulnerableParameters)];

        if (uniqueVulnerableParams.length > 0) {
            results.status = 'vulnerable';
            results.vulnerabilities.push({
                severity: 'HIGH',
                description: 'XSS vulnerability detected',
                details: `Vulnerable parameters: ${uniqueVulnerableParams.join(', ')}`
            });
            results.recommendations.push('URGENT: Implement proper output encoding/escaping');
            results.recommendations.push('Use Content Security Policy (CSP) headers');
            results.recommendations.push('Sanitize user input on both client and server side');
            results.recommendations.push('Use frameworks that auto-escape output by default');
            results.recommendations.push('Validate and whitelist allowed HTML tags if rich text is needed');
        } else {
            results.status = 'protected';
            results.recommendations.push('No XSS vulnerabilities detected');
            results.recommendations.push('Continue implementing proper output encoding');
            results.recommendations.push('Consider adding CSP headers for defense in depth');
        }

    } catch (error) {
        results.error = error.message;
        results.status = 'error';
    }

    return results;
}
