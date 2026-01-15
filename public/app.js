// API Base URL
const API_BASE = '/api/security';

// Test configurations
const testConfigs = {
    'brute-force': {
        endpoint: '/test/brute-force',
        getData: () => ({
            targetUrl: getTargetUrl(),
            endpoint: getEndpoint() || '/login',
            usernameField: 'username',
            passwordField: 'password',
            attempts: 50
        })
    },
    'rate-limiting': {
        endpoint: '/test/rate-limiting',
        getData: () => ({
            targetUrl: getTargetUrl(),
            endpoint: getEndpoint() || '/api',
            requestCount: 100,
            timeWindow: 1000
        })
    },
    'sql-injection': {
        endpoint: '/test/sql-injection',
        getData: () => ({
            targetUrl: getTargetUrl(),
            endpoint: getEndpoint() || '/api/users',
            parameters: ['id', 'user', 'search']
        })
    },
    'xss': {
        endpoint: '/test/xss',
        getData: () => ({
            targetUrl: getTargetUrl(),
            endpoint: getEndpoint() || '/api/comments',
            parameters: ['name', 'comment', 'message']
        })
    },
    'security-headers': {
        endpoint: '/test/security-headers',
        getData: () => ({
            targetUrl: getTargetUrl()
        })
    },
    'cors': {
        endpoint: '/test/cors',
        getData: () => ({
            targetUrl: getTargetUrl()
        })
    },
    'jwt': {
        endpoint: '/test/jwt',
        getData: () => {
            const token = prompt('Enter JWT token to analyze:');
            if (!token) throw new Error('JWT token is required');
            return { token };
        }
    },
    'authentication': {
        endpoint: '/test/authentication',
        getData: () => ({
            targetUrl: getTargetUrl(),
            endpoint: getEndpoint() || '/login',
            credentials: {
                username: 'testuser',
                password: 'testpass'
            }
        })
    },
    'endpoint-discovery': {
        endpoint: '/test/discover-endpoints',
        getData: () => ({
            targetUrl: getTargetUrl(),
            commonPaths: []
        })
    },
    'timing-attacks': {
        endpoint: '/test/timing-attacks',
        getData: () => ({
            targetUrl: getTargetUrl(),
            endpoint: getEndpoint() || '/login',
            samples: 20
        })
    }
};

// Helper functions
function getTargetUrl() {
    const url = document.getElementById('targetUrl').value.trim();
    if (!url) {
        throw new Error('Please enter a target URL');
    }
    return url;
}

function getEndpoint() {
    return document.getElementById('endpoint').value.trim();
}

function showLoading() {
    document.getElementById('loadingOverlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loadingOverlay').style.display = 'none';
}

function showResults() {
    document.getElementById('resultsSection').style.display = 'block';
    document.getElementById('resultsSection').scrollIntoView({ behavior: 'smooth' });
}

// Run individual test
async function runTest(testName) {
    try {
        showLoading();

        const config = testConfigs[testName];
        if (!config) {
            throw new Error(`Unknown test: ${testName}`);
        }

        const data = config.getData();

        const response = await fetch(API_BASE + config.endpoint, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (response.ok) {
            displayResult(result);
        } else {
            displayError(result.error || 'Test failed');
        }
    } catch (error) {
        displayError(error.message);
    } finally {
        hideLoading();
    }
}

// Run all tests
async function runAllTests() {
    try {
        showLoading();
        clearResults();

        const testNames = Object.keys(testConfigs).filter(name => name !== 'jwt');

        for (const testName of testNames) {
            try {
                const config = testConfigs[testName];
                const data = config.getData();

                const response = await fetch(API_BASE + config.endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify(data)
                });

                const result = await response.json();

                if (response.ok) {
                    displayResult(result);
                } else {
                    console.error(`Test ${testName} failed:`, result.error);
                }

                // Small delay between tests
                await new Promise(resolve => setTimeout(resolve, 500));
            } catch (error) {
                console.error(`Test ${testName} error:`, error);
            }
        }
    } catch (error) {
        displayError(error.message);
    } finally {
        hideLoading();
    }
}

// Display result
function displayResult(result) {
    showResults();

    const resultsContent = document.getElementById('resultsContent');

    const resultDiv = document.createElement('div');
    resultDiv.className = 'result-item';

    // Determine border color based on status
    const statusColors = {
        'vulnerable': '#ef4444',
        'weak': '#f59e0b',
        'protected': '#10b981',
        'secure': '#10b981',
        'good': '#10b981',
        'excellent': '#10b981',
        'error': '#ef4444'
    };

    resultDiv.style.borderLeftColor = statusColors[result.status] || '#6366f1';

    let html = `
        <div class="result-header">
            <h3 class="result-title">${result.testName}</h3>
            <span class="status-badge status-${result.status}">${result.status}</span>
        </div>
        <p><strong>Target:</strong> ${result.targetUrl || 'N/A'}</p>
        <p><strong>Timestamp:</strong> ${new Date(result.timestamp).toLocaleString()}</p>
    `;

    // Display vulnerabilities
    if (result.vulnerabilities && result.vulnerabilities.length > 0) {
        html += '<div class="vulnerability-list"><h4>Vulnerabilities Found:</h4>';
        result.vulnerabilities.forEach(vuln => {
            const severityClass = vuln.severity.toLowerCase();
            html += `
                <div class="vulnerability-item ${severityClass}">
                    <span class="severity ${vuln.severity}">${vuln.severity}</span>
                    <p><strong>${vuln.description}</strong></p>
                    <p>${vuln.details}</p>
                </div>
            `;
        });
        html += '</div>';
    }

    // Display key metrics
    if (result.totalAttempts !== undefined) {
        html += `<p><strong>Total Attempts:</strong> ${result.totalAttempts}</p>`;
    }
    if (result.blockedAttempts !== undefined) {
        html += `<p><strong>Blocked Attempts:</strong> ${result.blockedAttempts}</p>`;
    }
    if (result.successfulRequests !== undefined) {
        html += `<p><strong>Successful Requests:</strong> ${result.successfulRequests}</p>`;
    }
    if (result.rateLimitedRequests !== undefined) {
        html += `<p><strong>Rate Limited:</strong> ${result.rateLimitedRequests}</p>`;
    }
    if (result.averageResponseTime !== undefined) {
        html += `<p><strong>Avg Response Time:</strong> ${result.averageResponseTime.toFixed(2)}ms</p>`;
    }
    if (result.foundEndpoints && result.foundEndpoints.length > 0) {
        html += `<p><strong>Found Endpoints:</strong> ${result.foundEndpoints.length}</p>`;
        html += `<p style="color: var(--text-muted); font-size: 0.875rem;">${result.foundEndpoints.join(', ')}</p>`;
    }
    if (result.presentHeaders && result.presentHeaders.length > 0) {
        html += `<p><strong>Security Headers Present:</strong> ${result.presentHeaders.length}</p>`;
    }
    if (result.missingHeaders && result.missingHeaders.length > 0) {
        html += `<p><strong>Missing Headers:</strong> ${result.missingHeaders.length}</p>`;
    }

    // Display recommendations
    if (result.recommendations && result.recommendations.length > 0) {
        html += '<div class="recommendations"><h4>Recommendations:</h4><ul>';
        result.recommendations.forEach(rec => {
            html += `<li>${rec}</li>`;
        });
        html += '</ul></div>';
    }

    // Display error if any
    if (result.error) {
        html += `<p style="color: var(--danger); margin-top: 1rem;"><strong>Error:</strong> ${result.error}</p>`;
    }

    resultDiv.innerHTML = html;
    resultsContent.appendChild(resultDiv);
}

// Display error
function displayError(message) {
    showResults();

    const resultsContent = document.getElementById('resultsContent');

    const errorDiv = document.createElement('div');
    errorDiv.className = 'result-item';
    errorDiv.style.borderLeftColor = '#ef4444';
    errorDiv.innerHTML = `
        <div class="result-header">
            <h3 class="result-title">Error</h3>
            <span class="status-badge status-vulnerable">ERROR</span>
        </div>
        <p style="color: var(--danger);">${message}</p>
    `;

    resultsContent.appendChild(errorDiv);
}

// Clear results
function clearResults() {
    document.getElementById('resultsContent').innerHTML = '';
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    console.log('Security API Checker initialized');

    // Add enter key support for inputs
    document.getElementById('targetUrl').addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            runAllTests();
        }
    });
});

// Export functions to global scope
window.runTest = runTest;
window.runAllTests = runAllTests;
