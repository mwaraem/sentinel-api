const axios = require("axios");

const scanSecurityHeaders = async (target) => {
    const response = await axios.get(target, {
        timeout: 10000,
        maxRedirects: 5,
        validateStatus: () => true,
    });

    const headers = response.headers;
    const findings = [];

    checkContentSecurityPolicy(headers, findings);
    checkStrictTransportSecurity(headers, findings);
    checkXContentTypeOptions(headers, findings);
    checkXFrameOptions(headers, findings);
    checkReferrerPolicy(headers, findings);

    return {
        statusCode: response.status,
        findings,
    };
};

const checkContentSecurityPolicy = (headers, findings) => {
    const value = headers["content-security-policy"];

    if (!value) {
        findings.push({
            type: "missing-security-header",
            severity: "high",
            title: "Content Security Policy (CSP) is missing",
            description:
                "The target does not define a Content-Security-Policy header.",
            recommendation:
                "Implement a restrictive Content-Security-Policy appropriate for the application.",
        });

        return;
    }

    if (value.includes("'unsafe-inline'")) {
        findings.push({
            type: "weak-security-header",
            severity: "medium",
            title: "CSP allows unsafe inline scripts",
            description:
                "The Content-Security-Policy allows 'unsafe-inline', which weakens protection against certain cross-site scripting attacks.",
            recommendation:
                "Avoid 'unsafe-inline' where possible and use nonces or hashes for inline scripts.",
        });
    }

    if (value.includes("'unsafe-eval'")) {
        findings.push({
            type: "weak-security-header",
            severity: "medium",
            title: "CSP allows unsafe eval",
            description:
                "The Content-Security-Policy allows 'unsafe-eval', which can weaken protection against script injection.",
            recommendation:
                "Remove 'unsafe-eval' unless it is strictly required by the application.",
        });
    }
};

const checkStrictTransportSecurity = (headers, findings) => {
    const value = headers["strict-transport-security"];

    if (!value) {
        findings.push({
            type: "missing-security-header",
            severity: "medium",
            title: "HTTP Strict Transport Security (HSTS) is missing",
            description:
                "The target does not define a Strict-Transport-Security header.",
            recommendation:
                "Configure HSTS to enforce HTTPS connections.",
        });

        return;
    }

    const maxAgeMatch = value.match(/max-age=(\d+)/i);

    if (!maxAgeMatch) {
        findings.push({
            type: "weak-security-header",
            severity: "medium",
            title: "HSTS has no valid max-age",
            description:
                "The Strict-Transport-Security header does not contain a valid max-age directive.",
            recommendation:
                "Configure HSTS with an appropriate max-age value.",
        });

        return;
    }

    const maxAge = Number(maxAgeMatch[1]);

    if (maxAge < 31536000) {
        findings.push({
            type: "weak-security-header",
            severity: "low",
            title: "HSTS max-age is too short",
            description:
                "The HSTS max-age is less than one year.",
            recommendation:
                "Consider using an HSTS max-age of at least 31536000 seconds.",
        });
    }
};

const checkXContentTypeOptions = (headers, findings) => {
    const value = headers["x-content-type-options"];

    if (!value) {
        findings.push({
            type: "missing-security-header",
            severity: "low",
            title: "X-Content-Type-Options is missing",
            description:
                "The target does not define X-Content-Type-Options.",
            recommendation:
                "Set X-Content-Type-Options to nosniff.",
        });

        return;
    }

    if (value.toLowerCase() !== "nosniff") {
        findings.push({
            type: "weak-security-header",
            severity: "low",
            title: "X-Content-Type-Options is incorrectly configured",
            description:
                "X-Content-Type-Options is present but is not set to nosniff.",
            recommendation:
                "Set X-Content-Type-Options to nosniff.",
        });
    }
};

const checkXFrameOptions = (headers, findings) => {
    const value = headers["x-frame-options"];

    if (!value) {
        findings.push({
            type: "missing-security-header",
            severity: "medium",
            title: "X-Frame-Options is missing",
            description:
                "The target does not define X-Frame-Options.",
            recommendation:
                "Set X-Frame-Options to DENY or SAMEORIGIN, or use an appropriate CSP frame-ancestors policy.",
        });

        return;
    }

    const normalizedValue = value.toUpperCase();

    if (
        normalizedValue !== "DENY" &&
        normalizedValue !== "SAMEORIGIN"
    ) {
        findings.push({
            type: "weak-security-header",
            severity: "medium",
            title: "X-Frame-Options is incorrectly configured",
            description:
                "X-Frame-Options contains an unsupported or unsafe value.",
            recommendation:
                "Use DENY or SAMEORIGIN, or configure CSP frame-ancestors.",
        });
    }
};

const checkReferrerPolicy = (headers, findings) => {
    const value = headers["referrer-policy"];

    if (!value) {
        findings.push({
            type: "missing-security-header",
            severity: "low",
            title: "Referrer-Policy is missing",
            description:
                "The target does not define a Referrer-Policy header.",
            recommendation:
                "Configure a restrictive Referrer-Policy.",
        });
    }
};

module.exports = {
    scanSecurityHeaders,
};