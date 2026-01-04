"""WAF detection - identify Web Application Firewalls."""

import re
from dataclasses import dataclass

import httpx


@dataclass
class WAFResult:
    """Detected WAF information."""

    name: str
    confidence: int
    evidence: str = ""


# WAF signatures
WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": {
            "server": r"cloudflare",
            "cf-ray": r".+",
            "cf-cache-status": r".+",
        },
        "cookies": ["__cfduid", "__cf_bm", "cf_clearance"],
    },
    "AWS WAF": {
        "headers": {
            "x-amzn-requestid": r".+",
        },
        "body": [r"Request blocked", r"AWS WAF"],
    },
    "Akamai": {
        "headers": {
            "server": r"AkamaiGHost",
            "x-akamai-": r".+",
        },
    },
    "Imperva/Incapsula": {
        "headers": {
            "x-iinfo": r".+",
            "x-cdn": r"Imperva|Incapsula",
        },
        "cookies": ["visid_incap_", "incap_ses_"],
    },
    "Sucuri": {
        "headers": {
            "server": r"Sucuri",
            "x-sucuri-id": r".+",
        },
    },
    "F5 BIG-IP": {
        "headers": {
            "server": r"BigIP|BIG-IP",
            "x-wa-info": r".+",
        },
        "cookies": ["BIGipServer", "TS"],
    },
    "Barracuda": {
        "headers": {
            "server": r"Barracuda",
        },
        "cookies": ["barra_counter_session"],
    },
    "ModSecurity": {
        "headers": {
            "server": r"mod_security|ModSecurity",
        },
        "body": [r"ModSecurity", r"NOYB"],
    },
    "Fortinet FortiWeb": {
        "headers": {
            "server": r"FortiWeb",
        },
        "cookies": ["FORTIWAFSID"],
    },
    "DenyAll": {
        "headers": {
            "server": r"DenyAll",
        },
    },
    "Radware AppWall": {
        "headers": {
            "x-sl-compstate": r".+",
        },
    },
    "Reblaze": {
        "headers": {
            "server": r"Reblaze",
        },
        "cookies": ["rbzid"],
    },
    "StackPath": {
        "headers": {
            "x-sp-": r".+",
            "server": r"StackPath",
        },
    },
    "Fastly": {
        "headers": {
            "x-fastly-request-id": r".+",
            "via": r"varnish",
        },
    },
    "KeyCDN": {
        "headers": {
            "server": r"KeyCDN",
        },
    },
    "Wallarm": {
        "headers": {
            "server": r"nginx-wallarm",
        },
    },
}


class WAFDetector:
    """Detect Web Application Firewalls."""

    def __init__(self, timeout: float = 15.0):
        """Initialize WAF detector.

        Args:
            timeout: Request timeout.
        """
        self.timeout = timeout

    async def detect(self, url: str) -> list[WAFResult]:
        """Detect WAF for a URL.

        Args:
            url: URL to analyze.

        Returns:
            List of detected WAFs.
        """
        results: list[WAFResult] = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Normal request
                response = await client.get(url, follow_redirects=True)
                headers = dict(response.headers)
                cookies = [c.name for c in response.cookies.jar]
                body = response.text

                # Check signatures
                for waf_name, signatures in WAF_SIGNATURES.items():
                    result = self._check_waf(waf_name, signatures, headers, cookies, body)
                    if result:
                        results.append(result)

                # Test with malicious payload (trigger WAF)
                if not results:
                    waf_result = await self._trigger_test(client, url)
                    if waf_result:
                        results.append(waf_result)

        except Exception:
            pass

        return results

    def _check_waf(
        self,
        name: str,
        signatures: dict,
        headers: dict,
        cookies: list[str],
        body: str,
    ) -> WAFResult | None:
        """Check if a WAF is present.

        Args:
            name: WAF name.
            signatures: Detection signatures.
            headers: Response headers.
            cookies: Response cookie names.
            body: Response body.

        Returns:
            WAFResult if detected, None otherwise.
        """
        confidence = 0
        evidence = ""

        # Check headers
        if "headers" in signatures:
            for header_name, pattern in signatures["headers"].items():
                for h_name, h_value in headers.items():
                    if header_name.lower() in h_name.lower():
                        if re.search(pattern, h_value, re.IGNORECASE):
                            confidence += 60
                            evidence = f"Header: {h_name}: {h_value[:50]}"
                            break

        # Check cookies
        if "cookies" in signatures:
            for cookie_pattern in signatures["cookies"]:
                for cookie_name in cookies:
                    if cookie_pattern.lower() in cookie_name.lower():
                        confidence += 40
                        evidence = evidence or f"Cookie: {cookie_name}"
                        break

        # Check body
        if "body" in signatures:
            for pattern in signatures["body"]:
                if re.search(pattern, body, re.IGNORECASE):
                    confidence += 50
                    evidence = evidence or f"Body pattern matched"
                    break

        if confidence > 0:
            return WAFResult(
                name=name,
                confidence=min(confidence, 100),
                evidence=evidence,
            )

        return None

    async def _trigger_test(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> WAFResult | None:
        """Test for WAF by sending suspicious payload.

        Args:
            client: HTTP client.
            url: Base URL.

        Returns:
            WAFResult if WAF detected.
        """
        # Simple payload to trigger WAF (harmless)
        test_payloads = [
            "?test=<script>alert(1)</script>",
            "?id=1' OR '1'='1",
            "?file=../../../etc/passwd",
        ]

        for payload in test_payloads:
            try:
                test_url = url.rstrip("/") + payload
                response = await client.get(test_url)

                # Check for WAF block indicators
                if response.status_code in [403, 406, 429, 503]:
                    blocked_patterns = [
                        (r"blocked", "Generic WAF"),
                        (r"access denied", "Generic WAF"),
                        (r"forbidden", "Generic WAF"),
                        (r"security", "Generic WAF"),
                        (r"firewall", "Generic WAF"),
                        (r"waf", "Generic WAF"),
                    ]

                    for pattern, waf_name in blocked_patterns:
                        if re.search(pattern, response.text, re.IGNORECASE):
                            return WAFResult(
                                name=waf_name,
                                confidence=70,
                                evidence=f"Blocked response ({response.status_code})",
                            )

                    # Generic block detection
                    return WAFResult(
                        name="Unknown WAF",
                        confidence=50,
                        evidence=f"HTTP {response.status_code} on test payload",
                    )

            except Exception:
                continue

        return None


async def quick_waf_check(url: str) -> WAFResult | None:
    """Quick WAF detection.

    Args:
        url: URL to check.

    Returns:
        First detected WAF or None.
    """
    detector = WAFDetector()
    results = await detector.detect(url)
    return results[0] if results else None
