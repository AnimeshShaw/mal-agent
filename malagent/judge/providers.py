"""Provider-agnostic text generation for the judge experiments.

Unlike malagent.models (the production narrative path, text-only), this
layer exposes what an experiment needs to be reproducible and costed:
temperature, seed, JSON mode, token counts and latency. Specs are
'<provider>:<model>', e.g. 'ollama:gemma4:12b', 'anthropic:claude-opus-5-5',
'openai:gpt-5.5', 'gemini:gemini-3.1-pro'. Cloud SDKs are imported lazily
and read their keys from the usual environment variables."""
from __future__ import annotations
import os
import time
from dataclasses import dataclass
from typing import Protocol


@dataclass
class GenResult:
    text: str
    provider: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    latency_ms: float = 0.0
    cached: bool = False


class GenProvider(Protocol):
    name: str
    model: str

    def generate(self, system: str, prompt: str, *, temperature: float = 0.0, seed: int = 0,
                 json_mode: bool = True, max_tokens: int = 1024) -> GenResult: ...


def parse_spec(spec: str) -> tuple[str, str]:
    provider, _, model = spec.partition(":")
    if not provider or not model:
        raise ValueError(f"provider spec must be '<provider>:<model>', got {spec!r}")
    return provider, model


class OllamaGen:
    name = "ollama"

    def __init__(self, model: str, base_url: str | None = None, num_ctx: int = 16384):
        self.model = model
        self.base_url = base_url or os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.num_ctx = num_ctx

    def generate(self, system, prompt, *, temperature=0.0, seed=0, json_mode=True, max_tokens=1024):
        import requests
        body = {"model": self.model, "stream": False, "think": False,
                "messages": [{"role": "system", "content": system},
                             {"role": "user", "content": prompt}],
                "options": {"temperature": temperature, "seed": seed, "num_ctx": self.num_ctx,
                            "num_predict": max_tokens}}
        if json_mode:
            body["format"] = "json"
        t0 = time.monotonic()
        r = requests.post(f"{self.base_url}/api/chat", json=body, timeout=900)
        r.raise_for_status()
        j = r.json()
        return GenResult(text=(j.get("message") or {}).get("content", ""), provider=self.name,
                         model=self.model, input_tokens=j.get("prompt_eval_count", 0) or 0,
                         output_tokens=j.get("eval_count", 0) or 0,
                         latency_ms=(time.monotonic() - t0) * 1000)


class AnthropicGen:
    name = "anthropic"

    def __init__(self, model: str):
        self.model = model

    def generate(self, system, prompt, *, temperature=0.0, seed=0, json_mode=True, max_tokens=1024):
        import anthropic
        client = anthropic.Anthropic()
        t0 = time.monotonic()
        # JSON is requested in the prompt; Anthropic has no seed parameter, so
        # repeated-run variance is measured with temperature > 0 instead.
        r = client.messages.create(model=self.model, max_tokens=max_tokens, system=system,
                                   temperature=temperature,
                                   messages=[{"role": "user", "content": prompt}])
        text = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
        return GenResult(text=text, provider=self.name, model=self.model,
                         input_tokens=r.usage.input_tokens, output_tokens=r.usage.output_tokens,
                         latency_ms=(time.monotonic() - t0) * 1000)


class OpenAIGen:
    name = "openai"

    def __init__(self, model: str, base_url: str | None = None, key_env: str = "OPENAI_API_KEY"):
        self.model, self.base_url, self.key_env = model, base_url, key_env

    def generate(self, system, prompt, *, temperature=0.0, seed=0, json_mode=True, max_tokens=1024):
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv(self.key_env), base_url=self.base_url)
        kwargs = dict(model=self.model, seed=seed, temperature=temperature,
                      max_completion_tokens=max_tokens,
                      messages=[{"role": "system", "content": system},
                                {"role": "user", "content": prompt}])
        if json_mode:
            kwargs["response_format"] = {"type": "json_object"}
        t0 = time.monotonic()
        r = client.chat.completions.create(**kwargs)
        u = r.usage
        return GenResult(text=r.choices[0].message.content or "", provider=self.name,
                         model=self.model, input_tokens=getattr(u, "prompt_tokens", 0),
                         output_tokens=getattr(u, "completion_tokens", 0),
                         latency_ms=(time.monotonic() - t0) * 1000)


class GeminiGen:
    name = "gemini"

    def __init__(self, model: str):
        self.model = model

    def generate(self, system, prompt, *, temperature=0.0, seed=0, json_mode=True, max_tokens=1024):
        from google import genai
        from google.genai import types
        client = genai.Client()
        cfg = types.GenerateContentConfig(system_instruction=system, temperature=temperature,
                                          seed=seed, max_output_tokens=max_tokens,
                                          response_mime_type="application/json" if json_mode else None)
        t0 = time.monotonic()
        r = client.models.generate_content(model=self.model, contents=prompt, config=cfg)
        u = getattr(r, "usage_metadata", None)
        return GenResult(text=r.text or "", provider=self.name, model=self.model,
                         input_tokens=getattr(u, "prompt_token_count", 0) or 0,
                         output_tokens=getattr(u, "candidates_token_count", 0) or 0,
                         latency_ms=(time.monotonic() - t0) * 1000)


def make_provider(spec: str) -> GenProvider:
    provider, model = parse_spec(spec)
    if provider == "ollama":
        return OllamaGen(model)
    if provider == "anthropic":
        return AnthropicGen(model)
    if provider == "openai":
        return OpenAIGen(model)
    if provider == "gemini":
        return GeminiGen(model)
    if provider == "xai":
        g = OpenAIGen(model, base_url="https://api.x.ai/v1", key_env="XAI_API_KEY")
        g.name = "xai"
        return g
    raise ValueError(f"unknown provider {provider!r}")
