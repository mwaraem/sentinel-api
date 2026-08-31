const SEVERITY_DEDUCTIONS = {
    critical: 30,
    high: 20,
    medium: 10,
    low: 5,
    info: 0,
};

const calculateSecurityScore = (findings) => {
    let score = 100;

    for (const finding of findings) {
        const deduction = SEVERITY_DEDUCTIONS[finding.severity] || 0;

        score -= deduction;
    }

    return Math.max(0, score);
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