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
    const results = await Promise.allSettled([
        scanSecurityHeaders(scan.target),
        scanTls(scan.target),
    ]);

    const findings = [];

    for (const result of results) {
        if (result.status === "fulfilled") {
            findings.push(...result.value.findings);
        }

        if (result.status === "rejected") {
            console.error(
                "Scanner failed:",
                result.reason
            );

            findings.push({
                type: "scanner-error",
                severity: "info",
                title: "A security scanner failed",
                description:
                    "One of Sentinel's security scanners could not complete successfully.",
                recommendation:
                    "Retry the scan and investigate the scanner error if the problem persists.",
            });
        }
    }

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