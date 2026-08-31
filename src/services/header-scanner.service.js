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
    checkCookies(headers, findings);

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

const checkCookies = (headers, findings) => {
    const setCookie = headers["set-cookie"];

    if (!setCookie || setCookie.length === 0) {
        return;
    }

    for (const cookie of setCookie) {
        analyzeCookie(cookie, findings);
    }
};

const analyzeCookie = (cookie, findings) => {
    const parts = cookie.split(";").map((part) => part.trim());

    const cookieName = parts[0]?.split("=")[0] || "Unknown";

    const attributes = parts.slice(1).map((part) => {
        const [name, ...valueParts] = part.split("=");

        return {
            name: name.toLowerCase(),
            value: valueParts.join("="),
        };
    });

    const hasSecure = attributes.some(
        (attribute) => attribute.name === "secure"
    );

    const hasHttpOnly = attributes.some(
        (attribute) => attribute.name === "httponly"
    );

    const sameSite = attributes.find(
        (attribute) => attribute.name === "samesite"
    );

    if (!hasSecure) {
        findings.push({
            type: "insecure-cookie",
            severity: "medium",
            title: `Cookie "${cookieName}" is missing Secure`,
            description:
                "The cookie does not have the Secure attribute, which means it may be transmitted over an unencrypted HTTP connection.",
            recommendation:
                "Add the Secure attribute to cookies that should only be transmitted over HTTPS.",
        });
    }

    if (!hasHttpOnly) {
        findings.push({
            type: "insecure-cookie",
            severity: "medium",
            title: `Cookie "${cookieName}" is missing HttpOnly`,
            description:
                "The cookie does not have the HttpOnly attribute, which allows client-side JavaScript to access it.",
            recommendation:
                "Add the HttpOnly attribute to sensitive cookies that do not need to be accessed by JavaScript.",
        });
    }

    if (!sameSite) {
        findings.push({
            type: "insecure-cookie",
            severity: "low",
            title: `Cookie "${cookieName}" is missing SameSite`,
            description:
                "The cookie does not explicitly define a SameSite policy.",
            recommendation:
                "Configure an appropriate SameSite value such as Lax or Strict.",
        });
    } else {
        const sameSiteValue = sameSite.value.toLowerCase();

        if (!["strict", "lax", "none"].includes(sameSiteValue)) {
            findings.push({
                type: "insecure-cookie",
                severity: "low",
                title: `Cookie "${cookieName}" has an invalid SameSite value`,
                description:
                    "The cookie contains a SameSite value that is not recognized.",
                recommendation:
                    "Use SameSite=Strict, SameSite=Lax, or SameSite=None as appropriate.",
            });
        }

        if (sameSiteValue === "none" && !hasSecure) {
            findings.push({
                type: "insecure-cookie",
                severity: "high",
                title: `Cookie "${cookieName}" uses SameSite=None without Secure`,
                description:
                    "Cookies using SameSite=None must also use the Secure attribute in modern browsers.",
                recommendation:
                    "Add the Secure attribute when using SameSite=None.",
            });
        }
    }
};

module.exports = {
    scanSecurityHeaders,
};