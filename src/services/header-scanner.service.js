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
            id: "missing-csp",
        });

        return;
    }

    if (value.includes("'unsafe-inline'")) {
        findings.push({
            id: "csp-unsafe-inline",
        });
    }

    if (value.includes("'unsafe-eval'")) {
        findings.push({
            id: "csp-unsafe-eval",
        });
    }
};

const checkStrictTransportSecurity = (headers, findings) => {
    const value = headers["strict-transport-security"];

    if (!value) {
        findings.push({
            id: "missing-hsts",
        });

        return;
    }

    const maxAgeMatch = value.match(/max-age=(\d+)/i);

    if (!maxAgeMatch) {
        findings.push({
            id: "hsts-no-max-age",
        });

        return;
    }

    const maxAge = Number(maxAgeMatch[1]);

    if (maxAge < 31536000) {
        findings.push({
            id: "hsts-max-age-too-short",
        });
    }
};

const checkXContentTypeOptions = (headers, findings) => {
    const value = headers["x-content-type-options"];

    if (!value) {
        findings.push({
            id: "missing-x-content-type-options",
        });

        return;
    }

    if (value.toLowerCase() !== "nosniff") {
        findings.push({
            id: "x-content-type-options-incorrect",
        });
    }
};

const checkXFrameOptions = (headers, findings) => {
    const value = headers["x-frame-options"];

    if (!value) {
        findings.push({
            id: "missing-x-frame-options",
        });

        return;
    }

    const normalizedValue = value.toUpperCase();

    if (
        normalizedValue !== "DENY" &&
        normalizedValue !== "SAMEORIGIN"
    ) {
        findings.push({
            id: "x-frame-options-incorrect",
        });
    }
};

const checkReferrerPolicy = (headers, findings) => {
    const value = headers["referrer-policy"];

    if (!value) {
        findings.push({
            id: "missing-referrer-policy",
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
            id: "cookie-missing-secure",
        });
    }

    if (!hasHttpOnly) {
        findings.push({
            id: "cookie-missing-httponly",
        });
    }

    if (!sameSite) {
        findings.push({
            id: "cookie-missing-samesite",
        });
    } else {
        const sameSiteValue = sameSite.value.toLowerCase();

        if (!["strict", "lax", "none"].includes(sameSiteValue)) {
            findings.push({
                id: "invalid-samesite-value",
            });
        }

        if (sameSiteValue === "none" && !hasSecure) {
            findings.push({
                id: "cookie-samesite-none-without-secure",
            });
        }
    }
};

module.exports = {
    scanSecurityHeaders,
};