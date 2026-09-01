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
                id: "cors-wildcard-credentials",
            });
        } else {
            findings.push({
                id: "cors-wildcard",
            });
        }
    }

    // Credentials without an explicit origin
    if (
        String(allowCredentials).toLowerCase() === "true" && !allowOrigin
    ) {
        findings.push({
            id: "cors-credentials-no-origin",
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