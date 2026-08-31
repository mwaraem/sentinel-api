const dns = require("dns").promises;
const net = require("net");

const isPrivateIPv4 = (ip) => {
    const parts = ip.split(".").map(Number);

    if (parts.length !== 4 || parts.some(Number.isNaN)) {
        return false;
    }

    const [a, b, c] = parts;

    return (
        a === 10 ||
        (a === 172 && b >= 16 && b <= 31) ||
        (a === 192 && b === 168) ||
        a === 127
    );
};

const validateTarget = async (target) => {
    let url;

    try {
        url = new URL(target);
    } catch {
        throw new Error("Invalid target URL");
    }

    if (!["http:", "https:"].includes(url.protocol)) {
        throw new Error("Only HTTP and HTTPS targets are allowed");
    }

    if (url.username || url.password) {
        throw new Error("Target URL must not contain credentials");
    }

    const hostname = url.hostname;

    if (
        hostname === "localhost" ||
        hostname.endsWith(".localhost") ||
        hostname === "0.0.0.0"
    ) {
        throw new Error("Local targets are not allowed");
    }

    if (net.isIP(hostname) === 4) {
        if (isPrivateIPv4(hostname)) {
            throw new Error("Private network targets are not allowed");
        }

        return url;
    }

    if (net.isIP(hostname) === 6) {
        throw new Error("IPv6 targets are not allowed");
    }

    const addresses = await dns.lookup(hostname, {
        all: true,
    });

    for (const address of addresses) {
        if (address.family === 4 && isPrivateIPv4(address.address)) {
            throw new Error("Target resolves to a private IP address");
        }
    }

    return url;
};

module.exports = {
    validateTarget,
};