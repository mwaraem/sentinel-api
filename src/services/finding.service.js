const VALID_SEVERITIES = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
];

const normalizeFinding = (finding) => {
    if (!finding || typeof finding !== "object") {
        throw new Error("Invalid finding");
    }

    const severity = String(
        finding.severity || "info"
    ).toLowerCase();

    if (!VALID_SEVERITIES.includes(severity)) {
        throw new Error(
            `Invalid finding severity: ${severity}`
        );
    }

    return {
        scanner: finding.scanner || "unknown",
        type: finding.type || "unknown",
        severity,
        title:
            finding.title ||
            "Security finding detected",
        description:
            finding.description ||
            "Sentinal detected a potential security issue.",
        recommendation:
            finding.recommendation ||
            "Review the finding and apply the recommended security controls.",
    };
};

const normalizeFindings = (findings = []) => {
    return findings.map(normalizeFinding);
};

module.exports = {
    normalizeFinding,
    normalizeFindings,
};