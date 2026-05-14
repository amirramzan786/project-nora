import datetime

# --- Smart Dark Mode (system + time-based) ---

def get_dark_mode_state():
    current_hour = datetime.datetime.now().hour

    # Dark mode active between 6PM and 7AM
    return current_hour >= 18 or current_hour <= 7


DARK_MODE = get_dark_mode_state()

# --- N.O.R.A THEME SYSTEM ---
THEME = {
    # --- CORE BACKGROUNDS ---
    "bg": "#020617",
    "card": "#0F172A",
    "card_alt": "#111827",

    # --- BORDERS ---
    "border": "#1E293B",

    # --- TEXT ---
    "text": "#F8FAFC",
    "muted": "#94A3B8",

    # --- ACCENTS ---
    "accent": "#2563EB",
    "success": "#22C55E",
    "warning": "#F59E0B",
    "danger": "#DC2626",

    # --- DEPTH ---
    "shadow": "0 8px 28px rgba(2,6,23,0.45)",
}