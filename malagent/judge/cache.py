"""Disk cache for generations: identical (provider, model, system, prompt,
temperature, seed, json_mode, max_tokens) never costs a second call.
Makes every experiment re-runnable for free and exactly reproducible."""
from __future__ import annotations
import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from .providers import GenResult


class CachedProvider:
    def __init__(self, inner, cache_dir):
        self.inner = inner
        self.name, self.model = inner.name, inner.model
        self.dir = Path(cache_dir)

    def _key(self, system, prompt, temperature, seed, json_mode, max_tokens) -> str:
        blob = json.dumps([self.name, self.model, system, prompt, temperature, seed, json_mode,
                           max_tokens], ensure_ascii=False)
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()

    def generate(self, system, prompt, *, temperature=0.0, seed=0, json_mode=True, max_tokens=1024):
        k = self._key(system, prompt, temperature, seed, json_mode, max_tokens)
        p = self.dir / k[:2] / f"{k}.json"
        if p.exists():
            d = json.loads(p.read_text(encoding="utf-8"))
            d["cached"] = True
            return GenResult(**d)
        r = self.inner.generate(system, prompt, temperature=temperature, seed=seed,
                                json_mode=json_mode, max_tokens=max_tokens)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(asdict(r), ensure_ascii=False), encoding="utf-8")
        return r
