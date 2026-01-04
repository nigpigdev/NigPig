"""NigPig Premium Theme - Futuristic gradient theme system."""

# Primary gradient colors (Pink → Purple)
PRIMARY_GRADIENT = ("#ff6b9d", "#7c3aed")

# Secondary gradient colors (Cyan → Deep Blue)
SECONDARY_GRADIENT = ("#00d4ff", "#090979")

# Accent colors
ACCENT_CYAN = "#00d4ff"
ACCENT_PINK = "#ff6b9d"
ACCENT_PURPLE = "#7c3aed"
ACCENT_ORANGE = "#ff9f43"
ACCENT_GREEN = "#00e676"

# Background colors
BG_DARK = "#0a0a0f"
BG_DARKER = "#050508"
BG_CARD = "#12121a"
BG_CARD_HOVER = "#1a1a25"
BG_GLASS = "rgba(18, 18, 26, 0.7)"

# Text colors
TEXT_PRIMARY = "#ffffff"
TEXT_SECONDARY = "#a0a0b0"
TEXT_DIM = "#606070"
TEXT_ACCENT = "#00d4ff"

# Status colors
SUCCESS = "#00e676"
WARNING = "#ffab00"
ERROR = "#ff5252"
CRITICAL = "#ff1744"
INFO = "#448aff"

# Severity colors
SEVERITY_COLORS = {
    "critical": "#ff1744",
    "high": "#ff5252",
    "medium": "#ffab00",
    "low": "#448aff",
    "info": "#00e676",
}

# Border colors
BORDER_DEFAULT = "#2a2a35"
BORDER_GLOW = "#00d4ff"
BORDER_ACCENT = "#ff6b9d"


class PremiumTheme:
    """Premium theme configuration for CustomTkinter."""

    # Window
    WINDOW_BG = BG_DARK

    # Sidebar
    SIDEBAR_BG = BG_DARKER
    SIDEBAR_WIDTH = 220
    SIDEBAR_ITEM_HEIGHT = 45
    SIDEBAR_ITEM_RADIUS = 10

    # Cards
    CARD_BG = BG_CARD
    CARD_HOVER_BG = BG_CARD_HOVER
    CARD_RADIUS = 16
    CARD_BORDER_WIDTH = 1
    CARD_BORDER_COLOR = BORDER_DEFAULT

    # Buttons
    BTN_PRIMARY_BG = ACCENT_PINK
    BTN_PRIMARY_HOVER = "#e05585"
    BTN_SECONDARY_BG = BG_CARD
    BTN_SECONDARY_HOVER = BG_CARD_HOVER
    BTN_RADIUS = 10
    BTN_HEIGHT = 42

    # Text
    TITLE_SIZE = 28
    HEADING_SIZE = 20
    BODY_SIZE = 14
    SMALL_SIZE = 12

    # Fonts
    FONT_FAMILY = "Segoe UI"
    FONT_MONO = "Consolas"

    # Animation
    TRANSITION_MS = 300

    # Glow effect colors
    GLOW_PINK = "#ff6b9d40"
    GLOW_CYAN = "#00d4ff40"
    GLOW_PURPLE = "#7c3aed40"


# Icon mappings
ICONS = {
    "dashboard": "📊",
    "carrot": "🥕",
    "recon": "🔍",
    "fingerprint": "🔬",
    "vuln": "🧪",
    "secrets": "🔐",
    "audit": "🛡️",
    "terminal": "💻",
    "settings": "⚙️",
    "history": "📋",
    "export": "📤",
    "scan": "🎯",
    "stop": "⏹️",
    "play": "▶️",
    "success": "✅",
    "warning": "⚠️",
    "error": "❌",
    "info": "ℹ️",
}


def get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    return SEVERITY_COLORS.get(severity.lower(), TEXT_SECONDARY)


def get_grade_color(grade: str) -> str:
    """Get color for SSL grade."""
    grade_colors = {
        "A+": SUCCESS,
        "A": SUCCESS,
        "B": "#8bc34a",
        "C": WARNING,
        "D": ERROR,
        "F": CRITICAL,
    }
    return grade_colors.get(grade.upper(), TEXT_SECONDARY)
