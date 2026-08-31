const Scan = require("../models/scan.model");

const {
    scanSecurityHeaders,
} = require("./header-scanner.service");

const {
    scanTls,
} = require("./tls-scanner.service");

const {
    calculateSecurityScore,
} = require("./security-score.service");

const runScan = async (scan) => {
    const headerResult = await scanSecurityHeaders(
        scan.target
    );

    const tlsResult = await scanTls(
        scan.target
    );

    const findings = [
        ...headerResult.findings,
        ...tlsResult.findings,
    ];

    const score = calculateSecurityScore(
        findings
    );

    scan.status = "completed";
    scan.score = score;
    scan.findings = findings;

    await scan.save();

    return scan;
};

module.exports = {
    runScan,
}