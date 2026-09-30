"""JSON-lines security event logger (ready to be shipped to Wazuh/ELK)."""
import json, os, time, hashlib, threading

LOG_PATH = os.environ.get("GATEWAY_LOG", "logs/security_events.jsonl")
_lock = threading.Lock()


def log_event(client, action, reasons, scan, prompt):
    os.makedirs(os.path.dirname(LOG_PATH) or ".", exist_ok=True)
    event = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "event_type": "llm_gateway",
        "client": client,
        "action": action,
        "reasons": reasons,
        "injection_score": scan.injection_score,
        "injection_rules": [h["rule"] for h in scan.injection_hits],
        "mitre_atlas_hint": "AML.T0051 LLM Prompt Injection" if scan.injection_hits else None,
        "secret_types": sorted({s[0] for s in scan.secrets}),
        "pii_types": sorted({p[0] for p in scan.pii}),
        # Never store raw sensitive prompts: keep a hash + length only
        "prompt_sha256": hashlib.sha256(prompt.encode()).hexdigest()[:16],
        "prompt_length": len(prompt),
    }
    with _lock, open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")
    return event
