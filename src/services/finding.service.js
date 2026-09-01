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

const aggregateFindings = (findings = []) => {
    const grouped = new Map();

    for (const finding of findings) {
        const key = `${finding.id}:${finding.scanner}`;

        if (!grouped.has(key)) {
            grouped.set(key, {
                id: finding.id,
                scanner: finding.scanner,
                type: finding.type,
                severity: finding.severity,
                title: finding.title,
                description: finding.description,
                impact: finding.impact,
                recommendation: finding.recommendation,
                cwe: finding.cwe,
                owasp: finding.owasp,
                occurrences: 1,
                metadata: {
                    ...finding.metadata,
                },
            });

            continue;
        }

        const existing = grouped.get(key);

        existing.occurrences += 1;

        if (
            finding.metadata &&
            Object.keys(finding.metadata).length > 0
        ) {
            for (const [key, value] of Object.entries(
                finding.metadata
            )) {
                if (!(key in existing.metadata)) {
                    existing.metadata[key] = value;
                    continue;
                }

                if (
                    Array.isArray(
                        existing.metadata[key]
                    )
                ) {
                    existing.metadata[key] = [
                        existing.metadata[key],
                        value,
                    ];
                }
            }
        }
    }

    return Array.from(grouped.values());
};

module.exports = {
    normalizeFinding,
    normalizeFindings,
    aggregateFindings,
};