const axios = require("axios");

const scanCors = async (target) => {
    const response = await axios.get(target, {
        timeout: 10000,
        maxRedirects: 5,
        validateStatus: () => true,
    });

    const headers = response.headers;

    const findings = [];

    const allowOrigin = headers["access-control-allow-origin"];

    const allowCredentials = headers["access-control-allow-credentials"];

    const allowMethods = headers["access-control-allow-methods"];

    const allowHeaders = headers["access-control-allow-headers"];

    // Access-Control-Allow-Origin: *
    if (allowOrigin === "*") {
        if (
            String(allowCredentials).toLowerCase() === "true"
        ) {
            findings.push({
                type: "cors-misconfiguration",
                severity: "high",
                title: "CORS allows all origins with credentials",
                description: "The target allows requests from any origin while also allowing credentials.",
                recommendation: "Avoid using Access-Control-Allow-Origin: * together with credential requests. Restrict CORS to trusted origins.",
            });
        } else {
            findings.push({
                type: "cors-misconfiguration",
                severity: "low",
                title:
                    "CORS allows requests from any origin",
                description:
                    "The target uses a wildcard CORS policy that allows requests from any origin.",
                recommendation:
                    "Restrict Access-Control-Allow-Origin to trusted origins when cross-origin access does not need to be public.",
            });
        }
    }

    // Credentials without an explicit origin
    if (
        String(allowCredentials).toLowerCase() === "true" && !allowOrigin
    ) {
        findings.push({
            type: "cors-misconfiguration",
            severity: "medium",
            title: "CORS credentials are enabled without an explicit origin",
            description: "The server enables credentialed CORS requests but does not explicitly define an allowed origin.",
            recommendation: "Define an explicit list of trusted origins when allowing credentials.",
        });
    }

    return {
        allowOrigin: allowOrigin || null,
        allowCredentials: allowCredentials || null,
        allowMethods: allowMethods || null,
        allowHeaders: allowHeaders || null,
        findings,
    };
};

module.exports = {
    scanCors,
};