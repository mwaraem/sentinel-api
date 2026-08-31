const axios = require("axios");

const SECURITY_HEADERS = [
    {
        name: "content-security-policy",
        title: "Content Security Policy (CSP)",
        severity: "high",
        description:
            "Content Security Policy is not configured. This can increase the impact of cross-site scripting and other content injection attacks.",
        recommendation:
            "Implement a restrictive Content-Security-Policy appropriate for the application.",
    },
    {
        name: "strict-transport-security",
        title: "HTTP Strict Transport Security (HSTS)",
        severity: "medium",
        description:
            "HTTP Strict Transport Security is not configured.",
        recommendation:
            "Configure Strict-Transport-Security to enforce HTTPS connections.",
    },
    {
        name: "x-content-type-options",
        title: "X-Content-Type-Options",
        severity: "low",
        description:
            "X-Content-Type-Options is not configured.",
        recommendation:
            "Set X-Content-Type-Options to nosniff.",
    },
    {
        name: "x-frame-options",
        title: "X-Frame-Options",
        severity: "medium",
        description:
            "X-Frame-Options is not configured.",
        recommendation:
            "Set X-Frame-Options to DENY or SAMEORIGIN, or use an appropriate CSP frame-ancestors policy.",
    },
    {
        name: "referrer-policy",
        title: "Referrer-Policy",
        severity: "low",
        description:
            "Referrer-Policy is not configured.",
        recommendation:
            "Configure a restrictive Referrer-Policy such as strict-origin-when-cross-origin.",
    },
];

const scanSecurityHeaders = async (target) => {
    const response = await axios.get(target, {
        timeout: 10000,
        maxRedirects: 5,
        validateStatus: () => true,
    });

    const headers = response.headers;

    const findings = [];

    for (const header of SECURITY_HEADERS) {
        if (!headers[header.name]) {
            findings.push({
                type: "missing-security-header",
                severity: header.severity,
                title: header.title,
                description: header.description,
                recommendation: header.recommendation,
            });
        }
    }

    return {
        statusCode: response.status,
        findings,
    };
};

module.exports = {
    scanSecurityHeaders,
};