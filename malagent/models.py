"""Model layer (D4/D5/D6). One ModelProvider interface, many backends.
Router tries LOCAL first, escalates to the configured CLOUD provider only when a
trigger fires AND the egress guard permits sending the artifact off-box.
If escalation is blocked and local can't resolve, callers mark the result
UNDETERMINED rather than guessing (fail-closed)."""
from __future__ import annotations
import hashlib
import json
import os
import time
from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable
from .contracts import AnalysisState, EgressPolicy, ModelCall, now
from .security import wrap_untrusted


@dataclass
class ModelResponse:
    text: str
    provider: str
    model: str
    location: str


@runtime_checkable
class ModelProvider(Protocol):
    name: str
    location: str          # "local" | "cloud"
    model: str
    def complete(self, system: str, prompt: str) -> str: ...


# ---- providers (SDKs imported lazily so missing packages don't break import) ----
class OllamaProvider:
    location = "local"
    def __init__(self, model: str = "qwen3:8b", base_url: Optional[str] = None):
        self.name = "ollama"; self.model = model
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    def complete(self, system: str, prompt: str) -> str:
        import requests
        r = requests.post(f"{self.base_url}/api/generate", json={
            "model": self.model, "system": system, "prompt": prompt, "stream": False,
        }, timeout=300)
        r.raise_for_status()
        return r.json().get("response", "")


class OpenAIProvider:
    location = "cloud"
    def __init__(self, model: str = "gpt-4o"):
        self.name = "openai"; self.model = model
    def complete(self, system: str, prompt: str) -> str:
        from openai import OpenAI
        c = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        r = c.chat.completions.create(model=self.model, messages=[
            {"role": "system", "content": system}, {"role": "user", "content": prompt}])
        return r.choices[0].message.content or ""


class AnthropicProvider:
    location = "cloud"
    def __init__(self, model: str = "claude-sonnet-4-6"):
        self.name = "anthropic"; self.model = model
    def complete(self, system: str, prompt: str) -> str:
        import anthropic
        c = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
        r = c.messages.create(model=self.model, max_tokens=1500, system=system,
                              messages=[{"role": "user", "content": prompt}])
        return "".join(b.text for b in r.content if getattr(b, "type", "") == "text")


class GeminiProvider:
    location = "cloud"
    def __init__(self, model: str = "gemini-3.1-pro-preview"):
        self.name = "gemini"; self.model = model
    def complete(self, system: str, prompt: str) -> str:
        import google.generativeai as genai
        genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
        m = genai.GenerativeModel(self.model, system_instruction=system)
        return m.generate_content(prompt).text or ""


class XAIProvider:
    """xAI Grok exposes an OpenAI-compatible endpoint."""
    location = "cloud"
    def __init__(self, model: str = "grok-2-latest"):
        self.name = "xai"; self.model = model
    def complete(self, system: str, prompt: str) -> str:
        from openai import OpenAI
        c = OpenAI(api_key=os.getenv("XAI_API_KEY"), base_url="https://api.x.ai/v1")
        r = c.chat.completions.create(model=self.model, messages=[
            {"role": "system", "content": system}, {"role": "user", "content": prompt}])
        return r.choices[0].message.content or ""


_PROVIDERS = {"ollama": OllamaProvider, "openai": OpenAIProvider,
              "anthropic": AnthropicProvider, "gemini": GeminiProvider, "xai": XAIProvider}


def build_provider(name: str, model: Optional[str] = None) -> ModelProvider:
    cls = _PROVIDERS[name]
    return cls(model) if model else cls()


# ---- egress guard (D6) ----
class EgressGuard:
    def __init__(self, policy: EgressPolicy):
        self.policy = policy

    def allowed(self, location: str, artifact_class: str) -> tuple[bool, str]:
        """artifact_class in {raw_bytes, pseudocode, hash_lookup, derived}."""
        if location == "local":
            return True, "local processing"
        if not self.policy.allow_cloud:
            return False, "cloud disabled by policy"
        if artifact_class == "raw_bytes" and not self.policy.allow_raw_bytes_egress:
            return False, "raw sample bytes may not leave the environment"
        if artifact_class == "pseudocode" and not self.policy.allow_pseudocode_egress:
            return False, "pseudocode egress not permitted for this client"
        if artifact_class == "hash_lookup" and not self.policy.allow_hash_lookup:
            return False, "hash lookup egress not permitted for this client"
        return True, "permitted"


class ModelRouter:
    """Local-first, policy-gated escalation. Records every model call for audit."""
    def __init__(self, state: AnalysisState, local: ModelProvider,
                 escalation: Optional[ModelProvider] = None, audit=None):
        self.state = state
        self.local = local
        self.escalation = escalation
        self.guard = EgressGuard(state.policy)
        self.audit = audit

    def analyze(self, system: str, untrusted_label: str, untrusted_text: str,
                escalate: bool = False, artifact_class: str = "pseudocode") -> Optional[ModelResponse]:
        prompt = wrap_untrusted(untrusted_label, untrusted_text)
        phash = hashlib.sha256(prompt.encode()).hexdigest()[:16]

        provider, location = self.local, "local"
        if escalate and self.escalation is not None:
            ok, reason = self.guard.allowed("cloud", artifact_class)
            if ok and self.state.budget.cloud_calls_used < self.state.budget.max_cloud_calls:
                provider, location = self.escalation, "cloud"
            else:
                # fail-closed: do not silently downgrade a hard case
                self._record(self.escalation, "cloud", phash, False)
                if self.audit:
                    self.audit.log("egress_blocked", provider=self.escalation.name,
                                   reason=reason, prompt_hash=phash)
                self._maybe_log_prompt_response(system, prompt, self.escalation, "cloud",
                                                response=None, error=f"egress blocked: {reason}")
                return None

        t0 = time.monotonic()
        try:
            text = provider.complete(system, prompt)
        except Exception as e:
            duration_ms = (time.monotonic() - t0) * 1000.0
            self._record(provider, location, phash, location != "cloud", duration_ms=duration_ms)
            if self.audit:
                self.audit.log("model_error", provider=provider.name, error=str(e)[:200])
            self._maybe_log_prompt_response(system, prompt, provider, location,
                                            response=None, error=str(e)[:500])
            return None
        duration_ms = (time.monotonic() - t0) * 1000.0
        if location == "cloud":
            self.state.budget.cloud_calls_used += 1
        self._record(provider, location, phash, True, duration_ms=duration_ms)
        self._maybe_log_prompt_response(system, prompt, provider, location,
                                        response=text, error=None)
        return ModelResponse(text=text, provider=provider.name, model=provider.model, location=location)

    def _record(self, provider, location, phash, egress_allowed, duration_ms=None):
        # duration_ms is None (not 0) when no provider call was ever made --
        # e.g. the egress-blocked fail-closed path below, which records the
        # attempt for audit purposes without timing anything real.
        mc = ModelCall(provider=provider.name, model=provider.model, location=location,
                       prompt_hash=phash, egress_allowed=egress_allowed, duration_ms=duration_ms)
        self.state.model_calls.append(mc)
        if self.audit:
            self.audit.log("model_call", provider=provider.name, model=provider.model,
                           location=location, prompt_hash=phash, egress_allowed=egress_allowed)

    def _maybe_log_prompt_response(self, system, prompt, provider, location, *,
                                   response, error):
        """Opt-in (MAL_AGENT_PROMPT_LOG_PATH, unset by default) full
        prompt/response logging for prompt-quality iteration -- separate
        from the audit trail above, which deliberately only ever records
        a prompt HASH, never the actual content. The logged content
        includes untrusted, attacker-controllable text extracted from the
        sample (via wrap_untrusted), so this must stay opt-in, and a
        logging failure (e.g. an unwritable path) must never break real
        analysis -- it's a debugging aid, not a critical path."""
        path = os.getenv("MAL_AGENT_PROMPT_LOG_PATH")
        if not path:
            return
        try:
            entry = {
                "timestamp": now().isoformat(),
                "provider": provider.name, "model": provider.model, "location": location,
                "system": system, "prompt": prompt, "response": response, "error": error,
            }
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except Exception:
            pass
