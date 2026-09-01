const {
    findingDefinitions,
} = require("../data/finding-definitions");

const normalizeFinding = (finding) => {
    if (!finding || typeof finding !== "object") {
        throw new Error("Invalid finding");
    }

    if (!finding.id) {
        throw new Error(
            "Finding is missing an ID"
        );
    }

    const definition =
        findingDefinitions[finding.id];

    if (!definition) {
        throw new Error(
            `Unknown finding ID: ${finding.id}`
        );
    }

    return {
        id: finding.id,

        scanner: finding.scanner || "unknown",

        type: definition.category,

        severity: definition.severity,

        title: definition.title,

        description:
            definition.description,

        impact:
            definition.impact,

        recommendation:
            definition.recommendation,

        cwe: definition.cwe || null,

        owasp: definition.owasp || null,

        metadata:
            finding.metadata || {},
    };
};

const normalizeFindings = (findings = []) => {
    return findings.map(normalizeFinding);
};

module.exports = {
    normalizeFinding,
    normalizeFindings,
};