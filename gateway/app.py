"""FastAPI security gateway: inspect -> block/redact -> forward -> inspect response."""
from fastapi import FastAPI, Request
from pydantic import BaseModel
from .detectors import analyze, scan_secrets, scan_pii, redact
from .logger import log_event
from .llm import ask_llm

app = FastAPI(title="LLM Security Gateway", version="1.0")


class ChatRequest(BaseModel):
    prompt: str


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/chat")
def chat(req: ChatRequest, request: Request):
    client = request.client.host if request.client else "unknown"
    scan = analyze(req.prompt)
    log_event(client, scan.action, scan.reasons, scan, req.prompt)

    if scan.action == "block":
        return {"action": "block", "reasons": scan.reasons,
                "response": "Request blocked by security policy."}

    answer = ask_llm(scan.redacted_text)

    # Output filtering: stop the model leaking secrets/PII back
    out_findings = scan_secrets(answer) + scan_pii(answer)
    if out_findings:
        answer = redact(answer, out_findings)
        scan.reasons.append("sensitive data removed from model output")

    return {"action": scan.action, "reasons": scan.reasons, "response": answer}
