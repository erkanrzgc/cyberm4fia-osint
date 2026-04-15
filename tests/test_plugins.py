"""Plugin loader tests."""

from __future__ import annotations

from pathlib import Path

from core.config import ScanConfig
from core.models import ScanResult
from core.plugins import PluginRegistry, load_plugins


def _write_plugin(dir_: Path, name: str, body: str) -> None:
    dir_.mkdir(parents=True, exist_ok=True)
    (dir_ / f"{name}.py").write_text(body, encoding="utf-8")


def test_registry_runs_post_scan_hooks() -> None:
    reg = PluginRegistry()
    seen: list[str] = []

    def hook(result: ScanResult, cfg: ScanConfig) -> None:
        seen.append(f"{result.username}:{cfg.username}")

    reg.post_scan(hook)
    reg.run_post_scan(ScanResult(username="alice"), ScanConfig(username="alice"))
    assert seen == ["alice:alice"]


def test_registry_isolates_hook_failures() -> None:
    reg = PluginRegistry()

    def bad(result, cfg):
        raise RuntimeError("boom")

    called: list[str] = []

    def good(result, cfg):
        called.append(result.username)

    reg.post_scan(bad)
    reg.post_scan(good)
    # Should not raise — bad hook is logged and skipped.
    reg.run_post_scan(ScanResult(username="x"), ScanConfig(username="x"))
    assert called == ["x"]


def test_load_plugins_discovers_register_function(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins"
    _write_plugin(
        plugin_dir,
        "hello",
        "def register(registry):\n"
        "    def on_scan(result, cfg):\n"
        "        result.platforms.append('touched')\n"
        "    registry.post_scan(on_scan)\n",
    )

    registry = load_plugins(extra_dirs=[plugin_dir])
    assert len(registry.post_scan_hooks) == 1

    result = ScanResult(username="alice")
    registry.run_post_scan(result, ScanConfig(username="alice"))
    assert "touched" in result.platforms


def test_load_plugins_skips_underscore_and_broken(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins"
    _write_plugin(plugin_dir, "_private", "raise RuntimeError('should not load')\n")
    _write_plugin(plugin_dir, "broken", "raise RuntimeError('broken')\n")
    _write_plugin(
        plugin_dir,
        "ok",
        "def register(registry):\n"
        "    registry.post_scan(lambda r, c: None)\n",
    )

    registry = load_plugins(extra_dirs=[plugin_dir])
    assert len(registry.post_scan_hooks) == 1


def test_load_plugins_ignores_modules_without_register(tmp_path: Path) -> None:
    plugin_dir = tmp_path / "plugins"
    _write_plugin(plugin_dir, "noop", "X = 1\n")

    registry = load_plugins(extra_dirs=[plugin_dir])
    assert registry.post_scan_hooks == []
