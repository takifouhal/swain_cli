"""Typed structures for stable, user-facing plan outputs."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, TypedDict

SchemaPlan = Dict[str, Any]


class PlanSettings(TypedDict):
    patch_base_url: bool
    emit_patched_schema: Optional[str]
    parallel: int
    run_hooks: bool
    post_hooks: List[str]
    post_hooks_by_language: Dict[str, List[str]]
    schema_cache_ttl: Optional[str]
    no_schema_cache: bool


class PlanJava(TypedDict):
    command: Optional[str]


class PlanJavaOpts(TypedDict):
    options: List[str]
    provided: bool


class PlanEngine(TypedDict):
    mode: str
    java: PlanJava
    java_opts: PlanJavaOpts


class PlanJar(TypedDict):
    path: str
    cached: bool


class PlanGenerator(TypedDict):
    version: str
    jar: PlanJar


class PlanRun(TypedDict):
    language: str
    resolved_language: str
    out_dir: str
    generator_args: List[str]


class GenPlan(TypedDict):
    mode: str
    schema: SchemaPlan
    settings: PlanSettings
    engine: PlanEngine
    generator: PlanGenerator
    runs: List[PlanRun]
