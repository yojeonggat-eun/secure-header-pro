# (analysis key, header name, recommended value)
FIXES = [
    ("hsts", "Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
    ("csp", "Content-Security-Policy",
     "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';"),
    ("x_frame_options", "X-Frame-Options", "DENY"),
    ("x_content_type_options", "X-Content-Type-Options", "nosniff"),
    ("referrer_policy", "Referrer-Policy", "strict-origin-when-cross-origin"),
    ("permissions_policy", "Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
    ("cross_origin_opener_policy", "Cross-Origin-Opener-Policy", "same-origin"),
    ("cross_origin_resource_policy", "Cross-Origin-Resource-Policy", "same-origin"),
    ("cross_origin_embedder_policy", "Cross-Origin-Embedder-Policy", "require-corp"),
]

NO_CHANGES = "# All important security headers are already present. No changes needed."

NOTES = [
    "# NOTE: test before deploying. A strict CSP, COEP and CORP can break pages that load",
    "# third-party scripts, images or embeds. Treat the values below as a starting point.",
]


def _needs_fix(analysis: dict, key: str) -> bool:
    # Missing headers and weak/misconfigured ones both need a fix.
    # CSP is only auto-generated when it is missing: a CSP that exists but
    # contains unsafe directives must be reviewed by hand.
    status = analysis.get(key, {}).get("status")
    if key == "csp":
        return status == "Missing"
    return status in ("Missing", "Weak")


def _build(analysis: dict, title: str, where: str, fmt: str) -> str:
    lines = [f"# {title} Security Headers Configuration", f"# {where}", *NOTES, ""]
    fixes = []
    for key, name, value in FIXES:
        if _needs_fix(analysis, key):
            fixes.append(fmt.format(name=name, value=value))

    if analysis.get("csp", {}).get("status") == "Weak":
        fixes.append("# CSP contains unsafe directives: review it manually (not auto-generated).")

    if not fixes:
        return NO_CHANGES
    return "\n".join(lines + fixes)


def generate_nginx_config(analysis: dict) -> str:
    """Nginx config for missing/weak headers.

    Note: in Nginx, add_header lines in a location block replace (not add to)
    those set at server level, so repeat them there if you use location blocks.
    """
    return _build(analysis, "Nginx", "Add these lines inside your server { } block",
                  'add_header {name} "{value}" always;')


def generate_apache_config(analysis: dict) -> str:
    """Apache config for missing/weak headers."""
    return _build(analysis, "Apache", "Add these lines in your .htaccess or VirtualHost",
                  'Header always set {name} "{value}"')
