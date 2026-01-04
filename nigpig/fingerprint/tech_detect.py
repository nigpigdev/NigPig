"""Technology detection - identify frameworks, CMS, and server software."""

import re
from dataclasses import dataclass

import httpx
from bs4 import BeautifulSoup


@dataclass
class TechResult:
    """Detected technology."""

    name: str
    category: str
    version: str = ""
    confidence: int = 100
    evidence: str = ""


# Technology signatures database
TECH_SIGNATURES = {
    # Web Servers
    "nginx": {
        "category": "Web Server",
        "headers": {"server": r"nginx/?(\d+\.[\d.]+)?"},
    },
    "Apache": {
        "category": "Web Server",
        "headers": {"server": r"Apache/?(\d+\.[\d.]+)?"},
    },
    "IIS": {
        "category": "Web Server",
        "headers": {"server": r"Microsoft-IIS/?(\d+\.[\d.]+)?"},
    },
    "LiteSpeed": {
        "category": "Web Server",
        "headers": {"server": r"LiteSpeed"},
    },
    "Cloudflare": {
        "category": "CDN",
        "headers": {"server": r"cloudflare", "cf-ray": r".+"},
    },
    # Programming Languages
    "PHP": {
        "category": "Language",
        "headers": {"x-powered-by": r"PHP/?(\d+\.[\d.]+)?"},
        "cookies": {"PHPSESSID": r".+"},
    },
    "ASP.NET": {
        "category": "Framework",
        "headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r"(\d+\.[\d.]+)"},
        "cookies": {"ASP.NET_SessionId": r".+"},
    },
    "Express.js": {
        "category": "Framework",
        "headers": {"x-powered-by": r"Express"},
    },
    # CMS
    "WordPress": {
        "category": "CMS",
        "html": [
            r"wp-content/",
            r"wp-includes/",
            r'<meta name="generator" content="WordPress ?([\d.]+)?"',
        ],
        "headers": {"x-pingback": r"xmlrpc\.php"},
    },
    "Drupal": {
        "category": "CMS",
        "html": [
            r"Drupal\.settings",
            r"sites/default/files",
            r'<meta name="Generator" content="Drupal ?([\d.]+)?"',
        ],
        "headers": {"x-drupal-cache": r".+", "x-generator": r"Drupal"},
    },
    "Joomla": {
        "category": "CMS",
        "html": [r"/media/jui/", r'<meta name="generator" content="Joomla'],
    },
    "Shopify": {
        "category": "E-commerce",
        "html": [r"cdn\.shopify\.com", r"Shopify\.theme"],
        "headers": {"x-shopid": r".+"},
    },
    "Magento": {
        "category": "E-commerce",
        "html": [r"/skin/frontend/", r"Mage\.Cookies"],
        "cookies": {"frontend": r".+"},
    },
    # JavaScript Frameworks
    "React": {
        "category": "JS Framework",
        "html": [r"react\.production\.min\.js", r"_reactRootContainer", r"data-reactroot"],
    },
    "Vue.js": {
        "category": "JS Framework",
        "html": [r"vue\.runtime\.min\.js", r"Vue\.js", r"v-cloak", r"data-v-"],
    },
    "Angular": {
        "category": "JS Framework",
        "html": [r"ng-version=", r"angular\.min\.js", r"ng-app"],
    },
    "jQuery": {
        "category": "JS Library",
        "html": [r"jquery[.-](\d+\.[\d.]+)?\.min\.js", r"jQuery v?(\d+\.[\d.]+)?"],
    },
    "Bootstrap": {
        "category": "CSS Framework",
        "html": [
            r"bootstrap[.-](\d+\.[\d.]+)?\.min\.(js|css)",
            r'class="[^"]*\b(container|row|col-)\b',
        ],
    },
    "Tailwind": {
        "category": "CSS Framework",
        "html": [r"tailwindcss", r'class="[^"]*\b(flex|grid|px-|py-|mx-|my-)\b'],
    },
    # Analytics & Tracking
    "Google Analytics": {
        "category": "Analytics",
        "html": [r"google-analytics\.com/analytics\.js", r"gtag", r"UA-\d+-\d+", r"G-[A-Z0-9]+"],
    },
    "Google Tag Manager": {
        "category": "Analytics",
        "html": [r"googletagmanager\.com/gtm\.js", r"GTM-[A-Z0-9]+"],
    },
    "Hotjar": {
        "category": "Analytics",
        "html": [r"static\.hotjar\.com"],
    },
    # Security
    "reCAPTCHA": {
        "category": "Security",
        "html": [r"google\.com/recaptcha", r"g-recaptcha"],
    },
    "hCaptcha": {
        "category": "Security",
        "html": [r"hcaptcha\.com", r"h-captcha"],
    },
    # Hosting/Infrastructure
    "Amazon AWS": {
        "category": "Hosting",
        "headers": {"server": r"AmazonS3", "x-amz-": r".+"},
        "html": [r"s3\.amazonaws\.com", r"\.amazonaws\.com"],
    },
    "Vercel": {
        "category": "Hosting",
        "headers": {"server": r"Vercel", "x-vercel-": r".+"},
    },
    "Netlify": {
        "category": "Hosting",
        "headers": {"server": r"Netlify", "x-nf-request-id": r".+"},
    },
}


class TechDetector:
    """Detect technologies used by a website."""

    def __init__(self, timeout: float = 15.0):
        """Initialize tech detector.

        Args:
            timeout: Request timeout.
        """
        self.timeout = timeout

    async def detect(self, url: str) -> list[TechResult]:
        """Detect technologies for a URL.

        Args:
            url: URL to analyze.

        Returns:
            List of detected technologies.
        """
        results: list[TechResult] = []

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, follow_redirects=True)

                headers = dict(response.headers)
                cookies = {c.name: c.value for c in response.cookies.jar}
                html = response.text

                # Check each technology
                for tech_name, signatures in TECH_SIGNATURES.items():
                    result = self._check_technology(
                        tech_name,
                        signatures,
                        headers,
                        cookies,
                        html,
                    )
                    if result:
                        results.append(result)

        except Exception:
            pass

        return results

    def _check_technology(
        self,
        name: str,
        signatures: dict,
        headers: dict,
        cookies: dict,
        html: str,
    ) -> TechResult | None:
        """Check if a technology is present.

        Args:
            name: Technology name.
            signatures: Detection signatures.
            headers: Response headers.
            cookies: Response cookies.
            html: Response body.

        Returns:
            TechResult if detected, None otherwise.
        """
        category = signatures.get("category", "Unknown")
        version = ""
        evidence = ""
        confidence = 0

        # Check headers
        if "headers" in signatures:
            for header_name, pattern in signatures["headers"].items():
                header_value = headers.get(header_name.lower(), "")
                if header_value:
                    match = re.search(pattern, header_value, re.IGNORECASE)
                    if match:
                        confidence += 80
                        evidence = f"Header: {header_name}: {header_value[:50]}"
                        if match.groups():
                            version = match.group(1) or ""
                        break

        # Check cookies
        if "cookies" in signatures:
            for cookie_name, pattern in signatures["cookies"].items():
                cookie_value = cookies.get(cookie_name, "")
                if cookie_value:
                    match = re.search(pattern, cookie_value, re.IGNORECASE)
                    if match:
                        confidence += 70
                        evidence = evidence or f"Cookie: {cookie_name}"
                        break

        # Check HTML
        if "html" in signatures:
            for pattern in signatures["html"]:
                match = re.search(pattern, html, re.IGNORECASE)
                if match:
                    confidence += 60
                    evidence = evidence or f"HTML pattern: {pattern[:30]}"
                    if match.groups() and not version:
                        version = match.group(1) or ""
                    break

        if confidence > 0:
            return TechResult(
                name=name,
                category=category,
                version=version,
                confidence=min(confidence, 100),
                evidence=evidence,
            )

        return None

    async def detect_full(self, url: str) -> dict:
        """Get full technology report.

        Args:
            url: URL to analyze.

        Returns:
            Dictionary with categorized results.
        """
        techs = await self.detect(url)

        # Group by category
        by_category: dict[str, list[TechResult]] = {}
        for tech in techs:
            if tech.category not in by_category:
                by_category[tech.category] = []
            by_category[tech.category].append(tech)

        return {
            "url": url,
            "technologies": techs,
            "by_category": by_category,
            "summary": [f"{t.name} ({t.category})" for t in techs],
        }
