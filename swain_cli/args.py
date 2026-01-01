"""Argument models shared across swain_cli modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GenArgs:
    """Arguments for `swain_cli gen` and generator invocation."""

    out: str
    languages: List[str]
    generator_version: Optional[str] = None
    engine: str = "embedded"
    schema: Optional[str] = None
    crudsql_url: Optional[str] = None
    swain_base_url: Optional[str] = None
    swain_project_id: Optional[int] = None
    swain_connection_id: Optional[int] = None
    swain_tenant_id: Optional[str] = None
    config: Optional[str] = None
    templates: Optional[str] = None
    additional_properties: List[str] = field(default_factory=list)
    generator_arg: List[str] = field(default_factory=list)
    java_opts: List[str] = field(default_factory=list)
    system_properties: List[str] = field(default_factory=list)
    skip_validate_spec: bool = False
    verbose: bool = False


@dataclass
class InteractiveArgs:
    """Arguments for `swain_cli interactive`."""

    generator_version: Optional[str] = None
    java_opts: List[str] = field(default_factory=list)
    generator_args: List[str] = field(default_factory=list)
    swain_base_url: Optional[str] = None
    crudsql_url: Optional[str] = None
    engine: str = "embedded"
