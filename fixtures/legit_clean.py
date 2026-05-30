# SYNTHETIC fixture — legitimate code, must produce ZERO findings (no FP).
def add(a, b):
    return a + b


API_BASE_URL = "https://example.com/v1"
timeout_seconds = 30
greeting = "hello world, this is fine"

# --- R89-100b near-miss negatives — each is a deliberate ALMOST-match of a new
# rule and must produce ZERO findings (proves no FP and no Python/JS drift):
#   stripe test-mode (not _live_) -> sk_test_0123456789abcdefABCDEFij
#   stripe live but under 24 chars -> sk_live_short
#   google token under 35 chars -> AIzaShort
#   github fine-grained under 82 -> github_pat_short
#   slack webhook wrong host -> https://example.com/services/T0/B0/abcdefABCDEF0123456789mnop
