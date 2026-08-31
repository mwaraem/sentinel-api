const tls = require("tls");

const scanTls = (target) => {
    return new Promise((resolve, reject) => {
        let url;

        try {
            url = new URL(target);
        } catch {
            return reject(new Error("Invalid target URL"));
        }

        if (url.protocol !== "https:") {
            return resolve({
                secure: false,
                findings: [
                    {
                        type: "transport-security",
                        severity: "high",
                        title: "Target does not use HTTPS",
                        description:
                            "The target is using HTTP instead of HTTPS.",
                        recommendation:
                            "Configure the application to use HTTPS and redirect HTTP traffic to HTTPS.",
                    },
                ],
            });
        }

        const hostname = url.hostname;

        const socket = tls.connect(
            {
                host: hostname,
                port: 443,
                servername: hostname,
                rejectUnauthorized: false,
                timeout: 10000,
            },
            () => {
                try {
                    const certificate = socket.getPeerCertificate();

                    const findings = [];

                    if (!certificate || !certificate.valid_to) {
                        findings.push({
                            type: "tls-certificate",
                            severity: "high",
                            title: "TLS certificate could not be inspected",
                            description:
                                "Sentinel could not retrieve a valid TLS certificate from the target.",
                            recommendation:
                                "Verify that the target has a properly configured TLS certificate.",
                        });
                    } else {
                        const expiryDate = new Date(
                            certificate.valid_to
                        );

                        const now = new Date();

                        if (expiryDate < now) {
                            findings.push({
                                type: "tls-certificate",
                                severity: "high",
                                title: "TLS certificate has expired",
                                description:
                                    "The TLS certificate presented by the target is expired.",
                                recommendation:
                                    "Renew and correctly configure the TLS certificate.",
                            });
                        }

                        const daysUntilExpiry =
                            (expiryDate - now) /
                            (1000 * 60 * 60 * 24);

                        if (
                            daysUntilExpiry > 0 &&
                            daysUntilExpiry <= 30
                        ) {
                            findings.push({
                                type: "tls-certificate",
                                severity: "medium",
                                title: "TLS certificate expires soon",
                                description:
                                    `The TLS certificate expires in approximately ${Math.ceil(
                                        daysUntilExpiry
                                    )} days.`,
                                recommendation:
                                    "Renew the TLS certificate before it expires.",
                            });
                        }
                    }

                    const protocol =
                        socket.getProtocol();

                    if (
                        protocol === "TLSv1" ||
                        protocol === "TLSv1.1"
                    ) {
                        findings.push({
                            type: "weak-tls",
                            severity: "high",
                            title: "Deprecated TLS protocol detected",
                            description:
                                `The target is using ${protocol}, which is deprecated.`,
                            recommendation:
                                "Configure the server to support modern TLS versions such as TLS 1.2 or TLS 1.3.",
                        });
                    }

                    resolve({
                        secure: true,
                        protocol,
                        certificate: {
                            subject: certificate.subject,
                            issuer: certificate.issuer,
                            validFrom: certificate.valid_from,
                            validTo: certificate.valid_to,
                        },
                        findings,
                    });

                    socket.end();
                } catch (error) {
                    socket.destroy();
                    reject(error);
                }
            }
        );

        socket.on("error", (error) => {
            reject(
                new Error(
                    `TLS connection failed: ${error.message}`
                )
            );
        });

        socket.on("timeout", () => {
            socket.destroy();

            reject(
                new Error(
                    "TLS connection timed out"
                )
            );
        });
    });
};

module.exports = {
    scanTls,
};