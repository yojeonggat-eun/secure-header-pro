# Single source of truth for how many points each header is worth.
# The weights add up to exactly 100, so the final score is a true score out of 100.
MAX_POINTS = {
    "hsts": 20,
    "csp": 30,
    "x_frame_options": 10,
    "x_content_type_options": 10,
    "referrer_policy": 10,
    "permissions_policy": 8,
    "cross_origin_opener_policy": 4,
    "cross_origin_resource_policy": 3,
    "cross_origin_embedder_policy": 3,
    "x_xss_protection": 0,  # legacy header: reported, but not scored
    "server": 2,
}


def calculate_score(analysis: dict) -> dict:
    """Calculate total score and grade from analysis results."""
    total_score = 0
    max_score = 0

    for key, data in analysis.items():
        limit = MAX_POINTS.get(key, 0)
        # Never let a check earn more than its weight
        total_score += min(data.get("score", 0), limit)
        max_score += limit

    percentage = round((total_score / max_score) * 100) if max_score > 0 else 0

    if percentage >= 95:
        grade = "A+"
    elif percentage >= 85:
        grade = "A"
    elif percentage >= 70:
        grade = "B"
    elif percentage >= 55:
        grade = "C"
    elif percentage >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": percentage,
        "grade": grade,
        "raw_points": total_score,
        "max_points": max_score,
    }
