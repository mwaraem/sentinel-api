const SEVERITY_DEDUCTIONS = {
    critical: 30,
    high: 20,
    medium: 10,
    low: 5,
    info: 0,
};

const calculateSecurityScore = (findings = []) => {
    let score = 100;

    const breakdown = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
    };

    for (const finding of findings) {
        const severity = finding.severity;

        if (!(severity in breakdown)) {
            continue;
        }

        breakdown[severity] += 1;

        score -=
            SEVERITY_DEDUCTIONS[severity] || 0;
    }

    score = Math.max(
        0,
        Math.min(100, score)
    );

    return {
        score,
        breakdown,
    };
};

const getScoreRating = (score) => {
    if (score >= 90) {
        return "excellent";
    }

    if (score >= 75) {
        return "good";
    }

    if (score >= 50) {
        return "fair";
    }

    return "poor";
}

module.exports = {
    calculateSecurityScore,
    getScoreRating,
};