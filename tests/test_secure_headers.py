from secure_headers.analyzer import analyze_headers
from secure_headers.generator import generate_apache_config, generate_nginx_config
from secure_headers.report import generate_html_report
from secure_headers.scoring import MAX_POINTS, calculate_score

# A site that does everything right
BEST_HEADERS = {
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy": "default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
    "x-frame-options": "DENY",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "permissions-policy": "camera=()",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-origin",
    "cross-origin-embedder-policy": "require-corp",
    "x-xss-protection": "0",
}


def score_of(headers):
    return calculate_score(analyze_headers(headers))


def test_weights_add_up_to_100():
    assert sum(MAX_POINTS.values()) == 100


def test_perfect_headers_get_a_plus():
    result = score_of(BEST_HEADERS)
    assert result["score"] == 100
    assert result["grade"] == "A+"


def test_no_check_can_exceed_its_weight():
    analysis = analyze_headers(BEST_HEADERS)
    for key, data in analysis.items():
        assert data["score"] <= MAX_POINTS[key], key


def test_no_headers_get_an_f():
    assert score_of({})["grade"] == "F"


def test_referrer_policy_requires_exact_match():
    weak = analyze_headers({"referrer-policy": "no-referrer-when-downgrade"})
    assert weak["referrer_policy"]["status"] == "Weak"


def test_referrer_policy_uses_last_value():
    result = analyze_headers({"referrer-policy": "origin-when-cross-origin, strict-origin-when-cross-origin"})
    assert result["referrer_policy"]["status"] == "Good"


def test_hsts_max_age_zero_is_not_good():
    result = analyze_headers({"strict-transport-security": "max-age=0"})["hsts"]
    assert result["status"] == "Weak"
    assert result["score"] == 0


def test_hsts_is_case_insensitive():
    result = analyze_headers({"strict-transport-security": 'Max-Age="31536000"; IncludeSubDomains'})["hsts"]
    assert result["status"] == "Good"
    assert result["score"] == 20


def test_hsts_low_max_age_is_weak():
    result = analyze_headers({"strict-transport-security": "max-age=3600"})["hsts"]
    assert result["status"] == "Weak"


def test_csp_unsafe_directives_lower_the_score():
    clean = analyze_headers({"content-security-policy": "default-src 'self'"})["csp"]
    unsafe = analyze_headers({"content-security-policy": "default-src 'self' 'unsafe-inline' 'unsafe-eval'"})["csp"]
    assert unsafe["score"] < clean["score"]
    assert unsafe["status"] == "Weak"


def test_report_escapes_untrusted_header_values():
    payload = "<script>alert(1)</script>"
    analysis = analyze_headers({"server": payload})
    html = generate_html_report(
        "evil.test", analysis, calculate_score(analysis), "https://evil.test",
        generate_nginx_config(analysis), generate_apache_config(analysis),
    )
    assert payload not in html
    assert "&lt;script&gt;" in html


def test_generator_fixes_missing_and_weak_headers():
    analysis = analyze_headers({"strict-transport-security": "max-age=3600"})
    assert "Strict-Transport-Security" in generate_nginx_config(analysis)
    assert "Strict-Transport-Security" in generate_apache_config(analysis)


def test_generator_says_nothing_to_do_for_perfect_headers():
    analysis = analyze_headers(BEST_HEADERS)
    assert "No changes needed" in generate_nginx_config(analysis)
    assert "No changes needed" in generate_apache_config(analysis)
