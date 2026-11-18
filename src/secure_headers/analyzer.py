import re

try:  # works when imported as a package (tests, python -m)
    from .scoring import MAX_POINTS
except ImportError:  # works when cli.py is run directly as a script
    from scoring import MAX_POINTS

ONE_YEAR = 31536000
GOOD_REFERRER_POLICIES = {
    "no-referrer",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
}


def _result(status: str, message: str, score: int) -> dict:
    return {"status": status, "message": message, "score": score}


def _check_hsts(headers: dict) -> dict:
    hsts = headers.get("strict-transport-security")
    if not hsts:
        return _result("Missing", "HSTS header is missing", 0)

    # Directive names are case-insensitive and the value may be quoted
    match = re.search(r'max-age\s*=\s*"?(\d+)"?', hsts, re.IGNORECASE)
    if not match:
        return _result("Weak", "HSTS has no valid max-age, so browsers ignore it", 0)

    max_age = int(match.group(1))
    if max_age == 0:
        return _result("Weak", "max-age=0 turns HSTS off", 0)

    score = 10
    message = "HSTS is present"
    if max_age >= ONE_YEAR:
        status = "Good"
        score += 7
        message += " | Good max-age (>= 1 year)"
    else:
        status = "Weak"
        message += " | max-age is too low (< 1 year)"

    if re.search(r"includesubdomains", hsts, re.IGNORECASE):
        score += 3
        message += " | includeSubDomains present"

    return _result(status, message, min(score, MAX_POINTS["hsts"]))


def _check_csp(headers: dict) -> dict:
    csp = headers.get("content-security-policy")
    if not csp:
        return _result("Missing", "CSP header is missing", 0)

    score = MAX_POINTS["csp"]
    message = "CSP is present"
    if "unsafe-inline" in csp:
        score -= 16
        message += " | Contains 'unsafe-inline' (bad)"
    if "unsafe-eval" in csp:
        score -= 10
        message += " | Contains 'unsafe-eval' (bad)"

    status = "Present" if score == MAX_POINTS["csp"] else "Weak"
    return _result(status, message, max(score, 0))


def _check_x_frame_options(headers: dict) -> dict:
    xfo = headers.get("x-frame-options")
    if not xfo:
        return _result("Missing", "X-Frame-Options is missing", 0)
    if xfo.strip().upper() in ("DENY", "SAMEORIGIN"):
        return _result("Good", f"X-Frame-Options is set to {xfo}", MAX_POINTS["x_frame_options"])
    return _result("Weak", f"X-Frame-Options has weak value: {xfo}", 4)


def _check_x_content_type_options(headers: dict) -> dict:
    xcto = headers.get("x-content-type-options")
    if xcto and xcto.strip().lower() == "nosniff":
        return _result("Good", "X-Content-Type-Options is correctly set to nosniff",
                       MAX_POINTS["x_content_type_options"])
    return _result("Missing", "X-Content-Type-Options is missing or incorrect", 0)


def _check_referrer_policy(headers: dict) -> dict:
    rp = headers.get("referrer-policy")
    if not rp:
        return _result("Missing", "Referrer-Policy is missing", 0)

    # Browsers use the last policy they recognise, and values must match exactly
    # ("no-referrer-when-downgrade" is NOT the same as "no-referrer").
    effective = rp.split(",")[-1].strip().lower()
    if effective in GOOD_REFERRER_POLICIES:
        return _result("Good", f"Referrer-Policy is good: {rp}", MAX_POINTS["referrer_policy"])
    return _result("Weak", f"Referrer-Policy is weak: {rp}", 4)


def _check_simple_presence(headers: dict, header: str, key: str, label: str) -> dict:
    value = headers.get(header)
    if not value:
        return _result("Missing", f"{header.title()} is missing", 0)
    return _result("Present", f"{label} is set to {value}", MAX_POINTS[key])


def _check_x_xss_protection(headers: dict) -> dict:
    value = headers.get("x-xss-protection")
    if not value:
        return _result("Missing", "X-XSS-Protection is missing (legacy header, not scored)", 0)
    if value.strip() == "0":
        return _result("Good", "X-XSS-Protection is 0 (recommended; legacy header, not scored)", 0)
    return _result("Weak", f"X-XSS-Protection is {value} (legacy header; rely on CSP instead)", 0)


def _check_server(headers: dict) -> dict:
    server = headers.get("server")
    if not server:
        return _result("Good", "Server header is not present (good)", MAX_POINTS["server"])
    if re.search(r"\d", server):
        return _result("Weak", f"Server header reveals software/version: {server}", 0)
    return _result("Present", f"Server header present (no version shown): {server}", 1)


def analyze_headers(headers: dict) -> dict:
    """Analyze security headers and return detailed results.

    `headers` must have lower-case header names.
    """
    return {
        "hsts": _check_hsts(headers),
        "csp": _check_csp(headers),
        "x_frame_options": _check_x_frame_options(headers),
        "x_content_type_options": _check_x_content_type_options(headers),
        "referrer_policy": _check_referrer_policy(headers),
        "permissions_policy": _check_simple_presence(
            headers, "permissions-policy", "permissions_policy", "Permissions-Policy"),
        "cross_origin_opener_policy": _check_simple_presence(
            headers, "cross-origin-opener-policy", "cross_origin_opener_policy", "COOP"),
        "cross_origin_resource_policy": _check_simple_presence(
            headers, "cross-origin-resource-policy", "cross_origin_resource_policy", "CORP"),
        "cross_origin_embedder_policy": _check_simple_presence(
            headers, "cross-origin-embedder-policy", "cross_origin_embedder_policy", "COEP"),
        "x_xss_protection": _check_x_xss_protection(headers),
        "server": _check_server(headers),
    }
