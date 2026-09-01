const SEVERITIES = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
];

const getRiskLevel = (score) => {
    if (score >= 90) {
        return "low";
    }

    if (score >= 70) {
        return "medium";
    }

    if (score >= 40) {
        return "high";
    }

    return "critical";
};

const createScanSummary = (
    findings = [],
    score = 0
) => {
    const summary = {
        total: findings.length,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
        riskLevel: getRiskLevel(score),
    };

    for (const finding of findings) {
        const severity = finding.severity;

        if (SEVERITIES.includes(severity)) {
            summary[severity] += 1;
        }
    }

    return summary;
};

module.exports = {
    createScanSummary,
};