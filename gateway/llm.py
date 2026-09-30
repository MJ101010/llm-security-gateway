"""LLM backend: Ollama if reachable, otherwise a mock so the demo always runs."""
import os, requests

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://localhost:11434")
MODEL = os.environ.get("OLLAMA_MODEL", "llama3.2:1b")


def ask_llm(prompt: str) -> str:
    if os.environ.get("USE_MOCK_LLM", "0") == "1":
        return f"[mock LLM] I received your (sanitised) prompt: {prompt[:200]}"
    try:
        r = requests.post(f"{OLLAMA_URL}/api/generate",
                          json={"model": MODEL, "prompt": prompt, "stream": False}, timeout=60)
        r.raise_for_status()
        return r.json().get("response", "")
    except Exception as e:
        return f"[LLM backend unavailable: {e}. Set USE_MOCK_LLM=1 to demo without Ollama.]"
