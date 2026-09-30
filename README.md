# LLM Security Gateway

A lightweight security proxy that sits between users and a Large Language Model.
It inspects every prompt for **prompt injection**, **leaked secrets** and **PII**, blocks or redacts
risky requests, filters the model's reply, and writes **SOC-ready JSON logs** that plug straight into Wazuh.

## Problem
Employees paste API keys, customer data and source code into AI chatbots, and attackers use prompt
injection to make company chatbots leak data or ignore their rules (OWASP LLM01 and LLM02). Most
organisations have no visibility into this. This project adds a control point and a monitoring trail.

## Architecture
```
User/App --> [ FastAPI Gateway ] --> LLM (Ollama / mock)
                |   1. Scan prompt: injection score, secrets, PII
                |   2. BLOCK (injection) | REDACT (secrets/PII) | ALLOW
                |   3. Scan model output, redact leaks
                v
        logs/security_events.jsonl --> Wazuh (custom rules) --> Dashboard / Streamlit
```

## Features
- **Prompt injection detection:** 10 weighted rule families (instruction override, system prompt
  extraction, jailbreak personas, delimiter injection, exfiltration, obfuscation, etc.)
- **Secret detection:** AWS, GitHub, OpenAI-style, Google, Slack keys, JWTs, private keys, password assignments
- **PII detection (India-aware):** Aadhaar, PAN, Indian phone numbers, emails, credit cards (Luhn-validated), private IPs
- **Output filtering:** redacts secrets/PII if the model returns them
- **Privacy-safe logging:** stores a hash and length of the prompt, never the raw text
- **Wazuh integration:** decoder-free JSON logs + custom rules, including a brute-force-style
  "repeated injection attempts from one client" correlation rule
- **Streamlit dashboard** for blocked/redacted/allowed counts and top triggered rules

## Quick start
```bash
python -m venv .venv && source .venv/bin/activate    # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# Option A: no LLM needed (mock backend)
export USE_MOCK_LLM=1                                # Windows PowerShell: $env:USE_MOCK_LLM="1"
# Option B: real local LLM
#   install Ollama, then: ollama pull llama3.2:1b

uvicorn gateway.app:app --port 8000
./demo.sh                      # in another terminal (or use curl / http://localhost:8000/docs)
streamlit run dashboard.py     # SOC-style dashboard
```

## Evaluation
```bash
python -m tests.evaluate
```
Latest run (62 labelled prompts, full output in `docs/evaluation_results.md`):

| Metric | Result |
|---|---|
| Threat detection rate (injection + secrets + PII) | **92.3%** (36/39) |
| False positive rate on benign prompts | **4.3%** (1/23) |
| Standard injection prompts | 20/20 |
| Secrets / PII prompts | 15/15 |
| Avg scan latency | under 0.1 ms per prompt |

**Important caveat:** I tuned rule weights after seeing the first run on this same set, so these
numbers are optimistic. A fair test needs fresh prompts you have not seen. Add your own to
`tests/dataset.py` and report the new numbers.

## Known limitations (honest section)
- Rule-based detection misses **obfuscation** (`Ign0re prev1ous`), **indirect/semantic** attacks
  ("what were the first words you were given?") and **paraphrases** with no trigger phrase.
- A 10-digit order number starting with 6-9 is flagged as a phone number (false positive).
- English-centric rules; no multi-turn or indirect injection (via documents/web pages) analysis.
- No authentication or rate limiting on the API itself.

## Future improvements
1. Add an LLM-as-judge or fine-tuned classifier as a second layer for semantic attacks.
2. Swap regex PII for Microsoft Presidio (named-entity recognition).
3. Text normalisation (leetspeak, unicode homoglyphs, base64 auto-decode) before scanning.
4. API keys per client, rate limiting, and multi-turn context scoring.
5. Test against public datasets (e.g. garak, HackAPrompt) for a reliable benchmark.

## Wazuh integration
1. Point a `<localfile>` (JSON) at `logs/security_events.jsonl` on the gateway host.
2. Copy `wazuh/llm_gateway_rules.xml` to the manager's rules folder and restart it.
3. Alerts appear as rules 100101-100103 (blocked injection, redacted data, repeated attempts).

## Project structure
```
gateway/detectors.py   detection + redaction engine
gateway/app.py         FastAPI proxy (/chat, /health)
gateway/llm.py         Ollama backend + mock mode
gateway/logger.py      JSON security event logger
dashboard.py           Streamlit dashboard
tests/                 labelled dataset + evaluation script
wazuh/                 custom Wazuh rules
```

## Disclaimer
All secrets and PII in the test dataset are fake. This is a learning/portfolio project and should not
be relied on as the only protection for a production system.
