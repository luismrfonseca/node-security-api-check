# 🔒 Security API Checker

Professional API Security Testing Tool for penetration testing and vulnerability assessment.

![dashboard](https://github.com/luismrfonseca/securityapicheck/dashboard.png)

## ⚠️ Legal Disclaimer

**USE ONLY ON SYSTEMS YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST**

This tool is designed for security professionals and developers to test their own APIs. Unauthorized testing of systems you don't own is illegal and unethical.

## 🎯 Features

### Security Tests

1. **Brute Force Protection** - Tests if your API can withstand brute force attacks
2. **Rate Limiting** - Verifies rate limiting implementation
3. **SQL Injection** - Detects SQL injection vulnerabilities
4. **XSS (Cross-Site Scripting)** - Tests for XSS vulnerabilities
5. **Security Headers** - Analyzes HTTP security headers
6. **CORS Configuration** - Tests CORS settings for misconfigurations
7. **JWT Token Analysis** - Analyzes JWT tokens for security issues
8. **Authentication Security** - Tests authentication mechanisms
9. **Endpoint Discovery** - Discovers exposed endpoints
10. **Timing Attacks** - Detects timing attack vulnerabilities

## 🚀 Installation

```bash
# Install dependencies
npm install

# Start the server
npm start

# Development mode (with auto-reload)
npm run dev
```

## 📖 Usage

1. **Start the server**
   ```bash
   npm start
   ```

2. **Open your browser**
   Navigate to `http://localhost:3000`

3. **Configure target**
   - Enter your API URL (e.g., `https://api.example.com`)
   - Optionally specify an endpoint (e.g., `/api/login`)

4. **Run tests**
   - Click individual test buttons to run specific tests
   - Click "Run All Tests" to execute all tests sequentially

## 🛠️ API Endpoints

All tests are available via REST API:

- `POST /api/security/test/brute-force` - Brute force testing
- `POST /api/security/test/rate-limiting` - Rate limiting testing
- `POST /api/security/test/sql-injection` - SQL injection testing
- `POST /api/security/test/xss` - XSS testing
- `POST /api/security/test/security-headers` - Security headers analysis
- `POST /api/security/test/cors` - CORS testing
- `POST /api/security/test/jwt` - JWT analysis
- `POST /api/security/test/authentication` - Authentication testing
- `POST /api/security/test/discover-endpoints` - Endpoint discovery
- `POST /api/security/test/timing-attacks` - Timing attack testing

## 📊 Test Results

Each test provides:
- **Status**: vulnerable, weak, protected, secure, good, excellent
- **Vulnerabilities**: List of detected security issues with severity levels
- **Recommendations**: Actionable security improvements
- **Details**: Technical information about the test execution

### Severity Levels
- 🔴 **CRITICAL** - Immediate action required
- 🟠 **HIGH** - Important security issue
- 🟡 **MEDIUM** - Should be addressed
- 🔵 **LOW** - Minor improvement

## 🎨 Features

- **Modern UI** - Beautiful dark theme with glassmorphism effects
- **Real-time Testing** - See results as they happen
- **Comprehensive Reports** - Detailed vulnerability analysis
- **Professional Grade** - Industry-standard security tests
- **Easy to Use** - Intuitive interface for developers

## 🔧 Configuration

The tool can be configured by modifying:
- Test parameters in `tests/` directory
- Server settings in `server.js`
- UI customization in `public/styles.css`

## 📝 Example Test Request

```javascript
// Brute Force Test
POST /api/security/test/brute-force
Content-Type: application/json

{
  "targetUrl": "https://api.example.com",
  "endpoint": "/login",
  "usernameField": "username",
  "passwordField": "password",
  "attempts": 50
}
```

## 🛡️ Security Best Practices

Based on test results, implement:

1. **Rate Limiting** - Prevent abuse and brute force attacks
2. **Input Validation** - Sanitize all user inputs
3. **Security Headers** - Implement HSTS, CSP, X-Frame-Options, etc.
4. **Strong Authentication** - Use MFA, strong passwords, account lockout
5. **HTTPS Only** - Never transmit credentials over HTTP
6. **JWT Security** - Use strong secrets, short expiration times
7. **CORS Configuration** - Whitelist specific origins only
8. **Error Messages** - Don't leak sensitive information
9. **Constant-Time Comparison** - Prevent timing attacks
10. **Regular Testing** - Continuously test your security

## 📦 Dependencies

- **express** - Web server framework
- **axios** - HTTP client for testing
- **jsonwebtoken** - JWT token analysis
- **bcrypt** - Password hashing utilities
- **cors** - CORS middleware
- **helmet** - Security headers middleware

## 🤝 Contributing

This is a personal security testing tool. Feel free to customize it for your needs.

## 📄 License

MIT License - Use at your own risk

## 👨‍💻 Author

Created for personal API security testing and development projects.

---

**Remember**: Always test responsibly and only on systems you own or have permission to test!
