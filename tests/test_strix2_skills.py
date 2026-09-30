"""Tests for Strix 2's registered skill directory (the cloud pentest playbook)."""

from __future__ import annotations

from strix.skills import (
    get_available_skills,
    load_skills,
    register_skill_dir,
    registered_skill_dirs,
)
from strix.strix2_ext import install_strix2_extensions
from strix.utils.resource_paths import get_strix_resource_path


def _register() -> None:
    register_skill_dir(get_strix_resource_path("skills2"))


def test_aws_pentest_skill_is_discoverable() -> None:
    _register()
    cloud = get_available_skills().get("cloud", [])
    assert "aws_pentest" in {skill["name"] for skill in cloud}


def test_aws_pentest_skill_loads_with_workflow() -> None:
    _register()
    body = load_skills(["cloud/aws_pentest"])
    assert "aws_pentest" in body
    content = body["aws_pentest"]
    # References the strix-aws wrapper tools and the two-tier discipline.
    assert "aws_whoami" in content
    assert "create_candidate" in content
    assert "s3_get_object_head" in content


def test_install_registers_the_skill_dir() -> None:
    install_strix2_extensions(None)
    assert get_strix_resource_path("skills2") in registered_skill_dirs()
