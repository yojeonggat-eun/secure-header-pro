import httpx

USER_AGENT = "SecureHeaderPro/1.0 (security header scanner)"


def fetch_headers(url: str):
    """Fetch a URL and return its response headers (names lower-cased)."""
    url = url.strip()
    # Add https:// if the user only typed the domain (scheme check is case-insensitive)
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = httpx.get(
            url,
            follow_redirects=True,
            timeout=15,
            headers={"User-Agent": USER_AGENT},
        )
        headers = {key.lower(): value for key, value in response.headers.items()}
        return {
            "success": True,
            "url": str(response.url),
            "status_code": response.status_code,
            "headers": headers,
        }
    except Exception as e:
        return {"success": False, "error": str(e)}
