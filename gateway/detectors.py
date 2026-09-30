"""Detection engine: secrets, PII and prompt-injection detection + redaction."""
import re
from dataclasses import dataclass, field

# ---------- Secrets ----------
SECRET_PATTERNS = {
    "AWS_ACCESS_KEY": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "GITHUB_TOKEN": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    "OPENAI_STYLE_KEY": re.compile(r"\bsk-[A-Za-z0-9_\-]{20,}\b"),
    "GOOGLE_API_KEY": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "SLACK_TOKEN": re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"),
    "PRIVATE_KEY": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "JWT": re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"),
    "PASSWORD_ASSIGNMENT": re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key)\s*[=:]\s*['\"]?[^\s'\"]{6,}"),
}

# ---------- PII ----------
def _luhn_ok(number: str) -> bool:
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if not 13 <= len(digits) <= 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

PII_PATTERNS = {
    "EMAIL": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
    "IN_PHONE": re.compile(r"(?<!\d)(?:\+91[\s-]?)?[6-9]\d{9}(?!\d)"),
    "AADHAAR": re.compile(r"(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)"),
    "PAN": re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
    "CREDIT_CARD": re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)"),
    "IPV4_PRIVATE": re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b"),
}

# ---------- Prompt injection (weighted rules) ----------
# (name, regex, weight, tactic)
INJECTION_RULES = [
    ("ignore_previous", r"(?i)\b(ignore|disregard|forget|override)\b.{0,30}\b(previous|prior|above|earlier|all|your)\b.{0,30}\b(instructions?|rules?|prompts?|guidelines?)\b", 5, "instruction override"),
    ("reveal_system_prompt", r"(?i)\b(reveal|show|print|repeat|output|leak|display)\b.{0,40}\b(system prompt|initial prompt|hidden (instructions?|prompt)|your instructions)\b", 5, "system prompt extraction"),
    ("dan_jailbreak", r"(?i)\b(DAN|do anything now|developer mode|jailbreak(ed)?|no restrictions|without (any )?(restrictions|filters|limitations))\b", 4, "jailbreak persona"),
    ("role_override", r"(?i)\b(you are now|from now on you (are|will)|act as if you (have|had) no|pretend (you are|to be))\b", 3, "role override"),
    ("bypass_safety", r"(?i)\b(bypass|disable|turn off|circumvent)\b.{0,30}\b(safety|filter|guardrail|moderation|content polic(y|ies))\b", 5, "safety bypass"),
    ("fake_system_tag", r"(?i)(\[/?(system|inst)\]|<\s*/?system\s*>|###\s*system\s*:)", 4, "delimiter injection"),
    ("exfil_instruction", r"(?i)\b(send|post|forward|exfiltrate|upload)\b.{0,40}\b(to|at)\b.{0,20}(https?://|\S+@\S+)", 4, "data exfiltration"),
    ("encoded_payload", r"(?i)\b(base64|rot13|hex)\b.{0,30}\b(decode|decoded|and (execute|run|follow))\b", 4, "obfuscation"),
    ("hypothetical_bypass", r"(?i)\b(hypothetically|for a (story|novel|movie)|in a fictional world)\b.{0,60}\b(how to (make|build|hack|steal)|step[- ]by[- ]step)\b", 4, "roleplay bypass"),
    ("priority_claim", r"(?i)\b(this is (an )?(admin|developer|system) (message|override|command)|authorized by (the )?(admin|developer))\b", 4, "authority spoofing"),
]
_COMPILED_INJECTION = [(n, re.compile(p), w, t) for n, p, w, t in INJECTION_RULES]
INJECTION_THRESHOLD = 4


@dataclass
class ScanResult:
    action: str = "allow"            # allow | redact | block
    redacted_text: str = ""
    secrets: list = field(default_factory=list)
    pii: list = field(default_factory=list)
    injection_hits: list = field(default_factory=list)
    injection_score: int = 0
    reasons: list = field(default_factory=list)


def scan_secrets(text):
    return [(name, m.group(0)) for name, rx in SECRET_PATTERNS.items() for m in rx.finditer(text)]


def scan_pii(text):
    found = []
    for name, rx in PII_PATTERNS.items():
        for m in rx.finditer(text):
            val = m.group(0)
            if name == "CREDIT_CARD" and not _luhn_ok(val):
                continue
            found.append((name, val))
    return found


def scan_injection(text):
    hits, score = [], 0
    for name, rx, weight, tactic in _COMPILED_INJECTION:
        if rx.search(text):
            hits.append({"rule": name, "weight": weight, "tactic": tactic})
            score += weight
    return hits, score


def redact(text, findings):
    # Replace longest values first so overlapping matches don't corrupt output
    for label, value in sorted(set(findings), key=lambda f: -len(f[1])):
        text = text.replace(value, f"[REDACTED_{label}]")
    return text


def analyze(text: str) -> ScanResult:
    res = ScanResult(redacted_text=text)
    res.secrets = scan_secrets(text)
    res.pii = scan_pii(text)
    res.injection_hits, res.injection_score = scan_injection(text)

    if res.injection_score >= INJECTION_THRESHOLD:
        res.action = "block"
        res.reasons.append(f"prompt injection (score {res.injection_score})")
    if res.secrets or res.pii:
        res.redacted_text = redact(text, res.secrets + res.pii)
        if res.action != "block":
            res.action = "redact"
        if res.secrets:
            res.reasons.append("secrets detected: " + ", ".join(sorted({s[0] for s in res.secrets})))
        if res.pii:
            res.reasons.append("PII detected: " + ", ".join(sorted({p[0] for p in res.pii})))
    return res
