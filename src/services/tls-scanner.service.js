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
                        id: "http-not-secure",
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
                            id: "tls-certificate-error",
                        });
                    } else {
                        const expiryDate = new Date(
                            certificate.valid_to
                        );

                        const now = new Date();

                        if (expiryDate < now) {
                            findings.push({
                                id: "tls-certificate-expired",
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
                                id: "tls-certificate-expiring",
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
                            id: "weak-tls",
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