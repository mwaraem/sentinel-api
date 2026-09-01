const findingDefinitions = {
    "http-not-secure": {
        title: "Target does not use HTTPS",
        severity: "high",
        category: "transport-security",
        description:
            "The target is using HTTP instead of HTTPS, which can expose data transmitted between clients and the server to interception or modification.",
        impact:
            "Attackers may be able to intercept sensitive information or manipulate traffic between the client and server.",
        recommendation:
            "Configure the application to use HTTPS and redirect HTTP traffic to HTTPS.",
        cwe: "CWE-319",
        owasp: "A02:2021 - Cryptographic Failures",
    },

    "tls-certificate-expired": {
        title: "TLS certificate has expired",
        severity: "high",
        category: "transport-security",
        description:
            "The TLS certificate presented by the target has expired.",
        impact:
            "Users may receive certificate warnings and secure connections may fail validation.",
        recommendation:
            "Renew the TLS certificate and ensure the renewed certificate is correctly deployed.",
        cwe: "CWE-295",
        owasp: "A02:2021 - Cryptographic Failures",
    },

    "tls-certificate-expiring": {
        title: "TLS certificate expires soon",
        severity: "medium",
        category: "transport-security",
        description:
            "The TLS certificate presented by the target will expire soon.",
        impact:
            "If the certificate is not renewed, users may eventually encounter certificate errors or failed secure connections.",
        recommendation:
            "Renew the TLS certificate before its expiration date.",
        cwe: "CWE-295",
        owasp: "A02:2021 - Cryptographic Failures",
    },

    "weak-tls": {
        title: "Deprecated TLS protocol detected",
        severity: "high",
        category: "transport-security",
        description:
            "The target is using a deprecated TLS protocol version.",
        impact:
            "Deprecated protocols may expose applications to known cryptographic weaknesses.",
        recommendation:
            "Configure the server to support modern TLS versions such as TLS 1.2 or TLS 1.3.",
        cwe: "CWE-326",
        owasp: "A02:2021 - Cryptographic Failures",
    },

    "cors-wildcard": {
        title: "CORS allows requests from any origin",
        severity: "low",
        category: "cors",
        description:
            "The target uses a wildcard CORS policy that permits requests from any origin.",
        impact:
            "An overly permissive CORS policy can expose application resources to unintended cross-origin clients.",
        recommendation:
            "Restrict Access-Control-Allow-Origin to trusted origins when cross-origin access does not need to be public.",
        cwe: "CWE-942",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "cors-wildcard-credentials": {
        title: "CORS allows all origins with credentials",
        severity: "high",
        category: "cors",
        description:
            "The target indicates a wildcard CORS origin together with credentialed requests.",
        impact:
            "An unsafe credentialed CORS configuration can increase the risk of unauthorized cross-origin access to protected resources.",
        recommendation:
            "Avoid wildcard origins for credentialed requests. Restrict CORS to explicitly trusted origins.",
        cwe: "CWE-942",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "cookie-missing-secure": {
        title: "Cookie is missing Secure",
        severity: "medium",
        category: "cookies",
        description:
            "The cookie does not have the Secure attribute.",
        impact:
            "The browser may transmit the cookie over an unencrypted HTTP connection.",
        recommendation:
            "Add the Secure attribute to sensitive cookies that should only be transmitted over HTTPS.",
        cwe: "CWE-614",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "cookie-missing-httponly": {
        title: "Cookie is missing HttpOnly",
        severity: "medium",
        category: "cookies",
        description:
            "The cookie does not have the HttpOnly attribute.",
        impact:
            "Client-side JavaScript may be able to access the cookie, increasing the potential impact of certain cross-site scripting vulnerabilities.",
        recommendation:
            "Add the HttpOnly attribute to sensitive cookies that do not need to be accessed by JavaScript.",
        cwe: "CWE-1004",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "cookie-missing-samesite": {
        title: "Cookie is missing SameSite",
        severity: "low",
        category: "cookies",
        description:
            "The cookie does not explicitly define a SameSite policy.",
        impact:
            "The absence of an explicit SameSite policy can make cross-site cookie behavior less restrictive than intended.",
        recommendation:
            "Configure an appropriate SameSite value such as Lax or Strict.",
        cwe: "CWE-1275",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "cookie-samesite-none-without-secure": {
        title: "Cookie uses SameSite=None without Secure",
        severity: "high",
        category: "cookies",
        description:
            "The cookie uses SameSite=None without the Secure attribute.",
        impact:
            "Modern browsers require Secure for SameSite=None cookies, so the cookie may not behave as intended.",
        recommendation:
            "Add the Secure attribute when using SameSite=None.",
        cwe: "CWE-614",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "scanner-error": {
        title: "Security scanner failed",
        severity: "info",
        category: "scanner",
        description:
            "Sentinel was unable to complete a security check.",
        impact:
            "The affected area could not be assessed successfully.",
        recommendation:
            "Retry the scan and investigate the scanner error if the problem persists.",
    },

    "missing-csp": {
        title: "Content Security Policy (CSP) is missing",
        severity: "high",
        category: "headers",
        description:
            "The target does not define a Content-Security-Policy header.",
        impact:
            "Without CSP, the application is more vulnerable to cross-site scripting (XSS) attacks.",
        recommendation:
            "Implement a restrictive Content-Security-Policy appropriate for the application.",
        cwe: "CWE-693",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "csp-unsafe-inline": {
        title: "CSP allows unsafe inline scripts",
        severity: "medium",
        category: "headers",
        description:
            "The Content-Security-Policy allows 'unsafe-inline', which weakens protection against certain cross-site scripting attacks.",
        impact:
            "The application is more vulnerable to XSS attacks when unsafe-inline is permitted.",
        recommendation:
            "Avoid 'unsafe-inline' where possible and use nonces or hashes for inline scripts.",
        cwe: "CWE-693",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "csp-unsafe-eval": {
        title: "CSP allows unsafe eval",
        severity: "medium",
        category: "headers",
        description:
            "The Content-Security-Policy allows 'unsafe-eval', which can weaken protection against script injection.",
        impact:
            "The application is more vulnerable to script injection attacks.",
        recommendation:
            "Remove 'unsafe-eval' unless it is strictly required by the application.",
        cwe: "CWE-693",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "missing-hsts": {
        title: "HTTP Strict Transport Security (HSTS) is missing",
        severity: "medium",
        category: "headers",
        description:
            "The target does not define a Strict-Transport-Security header.",
        impact:
            "Without HSTS, clients may communicate with the server using unencrypted HTTP connections.",
        recommendation:
            "Configure HSTS to enforce HTTPS connections.",
        cwe: "CWE-319",
        owasp: "A02:2021 - Cryptographic Failures",
    },

    "hsts-no-max-age": {
        title: "HSTS has no valid max-age",
        severity: "medium",
        category: "headers",
        description:
            "The Strict-Transport-Security header does not contain a valid max-age directive.",
        impact:
            "The browser may not enforce the HSTS policy as intended.",
        recommendation:
            "Configure HSTS with an appropriate max-age value.",
        cwe: "CWE-319",
        owasp: "A02:2021 - Cryptographic Failures",
    },

    "hsts-max-age-too-short": {
        title: "HSTS max-age is too short",
        severity: "low",
        category: "headers",
        description:
            "The HSTS max-age is less than one year.",
        impact:
            "The browser may expire the HSTS policy sooner than ideal.",
        recommendation:
            "Consider using an HSTS max-age of at least 31536000 seconds.",
        cwe: "CWE-319",
        owasp: "A02:2021 - Cryptographic Failures",
    },

    "missing-x-content-type-options": {
        title: "X-Content-Type-Options is missing",
        severity: "low",
        category: "headers",
        description:
            "The target does not define X-Content-Type-Options.",
        impact:
            "Browsers may attempt to sniff the content type, potentially leading to security issues.",
        recommendation:
            "Set X-Content-Type-Options to nosniff.",
        cwe: "CWE-693",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "x-content-type-options-incorrect": {
        title: "X-Content-Type-Options is incorrectly configured",
        severity: "low",
        category: "headers",
        description:
            "X-Content-Type-Options is present but is not set to nosniff.",
        impact:
            "The protection against content-type sniffing attacks may not be effective.",
        recommendation:
            "Set X-Content-Type-Options to nosniff.",
        cwe: "CWE-693",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "missing-x-frame-options": {
        title: "X-Frame-Options is missing",
        severity: "medium",
        category: "headers",
        description:
            "The target does not define X-Frame-Options.",
        impact:
            "The application may be vulnerable to clickjacking attacks.",
        recommendation:
            "Set X-Frame-Options to DENY or SAMEORIGIN, or use an appropriate CSP frame-ancestors policy.",
        cwe: "CWE-1021",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "x-frame-options-incorrect": {
        title: "X-Frame-Options is incorrectly configured",
        severity: "medium",
        category: "headers",
        description:
            "X-Frame-Options contains an unsupported or unsafe value.",
        impact:
            "The clickjacking protection may not function as intended.",
        recommendation:
            "Use DENY or SAMEORIGIN, or configure CSP frame-ancestors.",
        cwe: "CWE-1021",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "missing-referrer-policy": {
        title: "Referrer-Policy is missing",
        severity: "low",
        category: "headers",
        description:
            "The target does not define a Referrer-Policy header.",
        impact:
            "Referrer information may leak to third-party sites via HTTP referer headers.",
        recommendation:
            "Configure a restrictive Referrer-Policy.",
        cwe: "CWE-1104",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "invalid-samesite-value": {
        title: "Cookie has an invalid SameSite value",
        severity: "low",
        category: "cookies",
        description:
            "The cookie contains a SameSite value that is not recognized.",
        impact:
            "The cookie behavior may not be as intended, potentially affecting CSRF protection.",
        recommendation:
            "Use SameSite=Strict, SameSite=Lax, or SameSite=None as appropriate.",
        cwe: "CWE-1275",
        owasp: "A05:2021 - Security Misconfiguration",
    },

    "tls-certificate-error": {
        title: "TLS certificate could not be inspected",
        severity: "high",
        category: "transport-security",
        description:
            "Sentinel could not retrieve a valid TLS certificate from the target.",
        impact:
            "The TLS configuration of the target could not be fully assessed.",
        recommendation:
            "Verify that the target has a properly configured TLS certificate.",
        cwe: "CWE-295",
        owasp: "A02:2021 - Cryptographic Failures",
    },

    "cors-credentials-no-origin": {
        title: "CORS credentials enabled without explicit origin",
        severity: "medium",
        category: "cors",
        description:
            "The server enables credentialed CORS requests but does not explicitly define an allowed origin.",
        impact:
            "Improper CORS configuration could allow unauthorized cross-origin requests with credentials.",
        recommendation:
            "Define an explicit list of trusted origins when allowing credentials.",
        cwe: "CWE-942",
        owasp: "A05:2021 - Security Misconfiguration",
    },
};

module.exports = {
    findingDefinitions,
};