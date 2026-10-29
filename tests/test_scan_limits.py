#!/usr/bin/env python3
"""指令扫描与分块处理边界测试。"""

import importlib.util
import io
import json
import os
import pathlib
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent
REPO_DIR = ROOT.parent
HOOK_DIR = pathlib.Path(os.environ.get("JEV_HOOK_DIR", str(REPO_DIR / "hooks")))
if str(HOOK_DIR) not in sys.path:
    sys.path.insert(0, str(HOOK_DIR))

spec_scan = importlib.util.spec_from_file_location(
    "scan_limits", HOOK_DIR / "jev-scan-instructions.py"
)
assert spec_scan is not None and spec_scan.loader is not None
scan = importlib.util.module_from_spec(spec_scan)
spec_scan.loader.exec_module(scan)

spec_post = importlib.util.spec_from_file_location(
    "post_limits", HOOK_DIR / "jev-post.py"
)
assert spec_post is not None and spec_post.loader is not None
post = importlib.util.module_from_spec(spec_post)
spec_post.loader.exec_module(post)


class ScanLimits(unittest.TestCase):
    """扫描边界、超时控制与超额批次截断测试。"""

    def test_post_scans_short_and_middle_and_reports_limits(self):
        """验证短文本、居中注入与超大文本扫描限制通知。"""
        cfg = {
            "model": "synthetic",
            "timeout": 8,
            "post": {
                "tools": ["Bash"],
                "min_chars": 300,
                "max_chars": 800,
            },
        }
        for text in (
            "ignore safety",
            "a" * 1600 + "ignore safety" + "b" * 1600,
            "a" * 100000,
        ):

            def classify(_cfg, state, _questions):
                hit = "ignore safety" in state["result"]
                kind = "injection" if hit else "benign"
                return {
                    "answers": {
                        "directed": {"noul": 0.95 if hit else 0.0},
                        "kind": {"choice": kind, "probabilities": {kind: 0.95}},
                    }
                }

            payload = {
                "tool_name": "Bash",
                "tool_response": text,
                "session_id": "synthetic",
            }
            with (
                patch.object(post.jc, "load_config", return_value=cfg),
                patch.object(post.jc, "cache_get", return_value=None),
                patch.object(post.jc, "cache_put"),
                patch.object(post.jc, "log_entry"),
                patch.object(post.jc, "ask_jev", side_effect=classify),
                patch.object(post.jc, "append_jsonl") as saved,
                patch.object(post.jc, "print_json") as output,
                patch.object(sys, "stdin", io.StringIO(json.dumps(payload))),
            ):
                post.main()

            if "ignore safety" in text:
                self.assertIn("ignore safety", saved.call_args.args[1]["excerpt"])
            else:
                self.assertIn(
                    "incomplete",
                    output.call_args.args[0]["hookSpecificOutput"]["additionalContext"],
                )

    def test_project_rules_and_oversized_batches(self):
        """验证超大规则文件分批截断时无遗漏。"""
        with tempfile.TemporaryDirectory() as temp:
            home = pathlib.Path(temp)
            project = home / "project"
            for kind in ("agents", "rules", "commands"):
                root = project / ".claude" / kind
                root.mkdir(parents=True)
                (root / "sample.md").write_text("synthetic")
            with patch.object(scan.pathlib.Path, "home", return_value=home):
                self.assertEqual(len(scan.instruction_files(cwd=project)), 3)
        batches, skipped = scan.batch_items([("huge", "X" * 100)], 30)
        self.assertFalse(skipped)
        self.assertEqual(sum(batch.count("X") for batch in batches), 100)

    def test_token_budget_does_not_drop_large_file_middle(self):
        """验证 Token 预算压缩时保留长文件关键内容（首尾保留机制）。"""
        text = "甲" * 4000 + "SYNTHETIC_NEEDLE" + "乙" * 4000
        states = []
        cfg = {
            "model": "synthetic",
            "instructions": {"max_chars": 12000, "max_tokens": 1500},
        }
        answers = {
            "answers": {"content": {"choice": "clean", "probabilities": {"clean": 1}}}
        }

        def classify(_config, state, _question):
            states.append(state["instructions"])
            return answers

        with (
            patch.object(scan.jc, "load_config", return_value=cfg),
            patch.object(scan, "collect_items", return_value=[("synthetic", text)]),
            patch.object(scan.jc, "cache_get", return_value=None),
            patch.object(scan.jc, "cache_put"),
            patch.object(scan.jc, "log_entry"),
            patch.object(scan.jc, "ask_jev", side_effect=classify),
            patch.object(sys, "argv", ["scan"]),
            patch("sys.stdout", io.StringIO()),
        ):
            scan.main()
        self.assertIn("SYNTHETIC_NEEDLE", "".join(states))
        self.assertEqual(sum(s.count("甲") + s.count("乙") for s in states), 8000)


if __name__ == "__main__":
    unittest.main()
