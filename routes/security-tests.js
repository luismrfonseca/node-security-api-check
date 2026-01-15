import express from 'express';
import {
    testBruteForce,
    testRateLimiting,
    testSQLInjection,
    testXSS,
    testSecurityHeaders,
    testCORS,
    testJWT,
    testAuthentication,
    discoverEndpoints,
    testTimingAttacks
} from '../tests/index.js';

const router = express.Router();

// Brute Force Testing
router.post('/test/brute-force', async (req, res) => {
    try {
        const { targetUrl, endpoint, usernameField, passwordField, attempts } = req.body;
        const results = await testBruteForce(targetUrl, endpoint, usernameField, passwordField, attempts);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// Rate Limiting Testing
router.post('/test/rate-limiting', async (req, res) => {
    try {
        const { targetUrl, endpoint, requestCount, timeWindow } = req.body;
        const results = await testRateLimiting(targetUrl, endpoint, requestCount, timeWindow);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// SQL Injection Testing
router.post('/test/sql-injection', async (req, res) => {
    try {
        const { targetUrl, endpoint, parameters } = req.body;
        const results = await testSQLInjection(targetUrl, endpoint, parameters);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// XSS Testing
router.post('/test/xss', async (req, res) => {
    try {
        const { targetUrl, endpoint, parameters } = req.body;
        const results = await testXSS(targetUrl, endpoint, parameters);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// Security Headers Testing
router.post('/test/security-headers', async (req, res) => {
    try {
        const { targetUrl } = req.body;
        const results = await testSecurityHeaders(targetUrl);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// CORS Testing
router.post('/test/cors', async (req, res) => {
    try {
        const { targetUrl } = req.body;
        const results = await testCORS(targetUrl);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// JWT Testing
router.post('/test/jwt', async (req, res) => {
    try {
        const { token } = req.body;
        const results = await testJWT(token);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// Authentication Testing
router.post('/test/authentication', async (req, res) => {
    try {
        const { targetUrl, endpoint, credentials } = req.body;
        const results = await testAuthentication(targetUrl, endpoint, credentials);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// Endpoint Discovery
router.post('/test/discover-endpoints', async (req, res) => {
    try {
        const { targetUrl, commonPaths } = req.body;
        const results = await discoverEndpoints(targetUrl, commonPaths);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

// Timing Attack Testing
router.post('/test/timing-attacks', async (req, res) => {
    try {
        const { targetUrl, endpoint, samples } = req.body;
        const results = await testTimingAttacks(targetUrl, endpoint, samples);
        res.json(results);
    } catch (error) {
        res.status(500).json({ error: error.message, stack: error.stack });
    }
});

export { router as securityTestRouter };
