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

const {
    scanCors,
} = require("./cors-scanner.service");

const {
    normalizeFindings,
} = require("./finding.service");

const scanners = [
    {
        name: "security-headers",
        scan: scanSecurityHeaders,
    },
    {
        name: "tls",
        scan: scanTls,
    },
    {
        name: "cors",
        scan: scanCors,
    },
];

const runScan = async (scan) => {
    const results = await Promise.allSettled(
        scanners.map((scanner) => 
            scanner.scan(scan.target)
                .then((result) => ({
                    scanner: scanner.name,
                    ...result,
                }))
        )
    );

    const findings = [];

    for (const result of results) {
        if (result.status === "fulfilled") {
            const scannerFindings = result.value.findings.map(
                (finding) => ({
                    ...finding,
                    scanner: result.value.scanner,
                })
            );

            findings.push(...scannerFindings);
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

    const normalizedFindings = normalizeFindings(findings);

    const score = calculateSecurityScore(
        normalizedFindings
    );

    scan.status = "completed";
    scan.score = score;
    scan.findings = normalizedFindings;

    await scan.save();

    return scan;
};

module.exports = {
    runScan,
}