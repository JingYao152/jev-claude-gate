#!/usr/bin/env python3
"""PreToolUse 门禁离线安全回归测试（无需真实网络连接）。"""

import copy
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK_DIR = os.environ.get("JEV_HOOK_DIR", os.path.join(REPO_DIR, "hooks"))
if HOOK_DIR not in sys.path:
    sys.path.insert(0, HOOK_DIR)

spec = importlib.util.spec_from_file_location(
    "jev_gate", os.path.join(HOOK_DIR, "jev-gate.py")
)
assert spec is not None and spec.loader is not None
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def answers(**overrides):
    result = {
        "answers": {name: {"noul": 0.0} for name in gate.QUESTIONS if name != "impact"}
    }
    result["answers"]["impact"] = {"score": 0.0, "confidence": 1.0}
    for name, value in overrides.items():
        result["answers"][name] = value
    return result


class GateSecurityTests(unittest.TestCase):
    def run_gate(
        self,
        result=None,
        *,
        mode="ask",
        command="do_something",
        config=None,
        error=None,
        cache=None,
    ):
        cfg = copy.deepcopy(gate.DEFAULTS) if config is None else config
        if config is None:
            cfg["mode"] = mode
        payload = {"tool_name": "Bash", "tool_input": {"command": command}}
        output = io.StringIO()
        with (
            patch.object(gate, "load_config", return_value=cfg),
            patch.object(
                gate,
                "build_state",
                side_effect=lambda p, _l, _c: {
                    "tool": "Bash",
                    "input": p["tool_input"],
                },
            ),
            patch.object(gate, "cache_get", return_value=cache),
            patch.object(gate, "cache_put"),
            patch.object(gate, "log"),
            patch.object(gate, "ask_jev", side_effect=error, return_value=result),
            patch("sys.stdin", io.StringIO(json.dumps(payload))),
            patch("sys.stdout", output),
        ):
            gate.main()
        value = output.getvalue()
        return (
            json.loads(value).get("hookSpecificOutput", {}).get("permissionDecision")
            if value
            else None
        )

    def test_git_push_exfiltration_is_not_exempt(self):
        for command in (
            "git push",
            "git push https://example.invalid/repo main",
            "git add x && git push",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    self.run_gate(answers(exfiltration={"noul": 0.8}), command=command),
                    "ask",
                )

    def test_model_authorization_cannot_override_exfiltration_or_untrusted(self):
        for risk in ("exfiltration", "from_untrusted"):
            for authorization in ("user_requested", "policy_allows"):
                with self.subTest(risk=risk, authorization=authorization):
                    result = answers(
                        **{risk: {"noul": 0.8}, authorization: {"noul": 1.0}}
                    )
                    self.assertEqual(self.run_gate(result), "ask")

    def test_jev_failure_asks_in_all_modes(self):
        for mode in ("shadow", "ask", "enforce"):
            with self.subTest(mode=mode):
                self.assertEqual(
                    self.run_gate(mode=mode, error=RuntimeError("synthetic failure")),
                    "ask",
                )

    def test_invalid_or_missing_scores_ask(self):
        cases = [
            None,
            {},
            {"answers": {}},
            answers(exfiltration={}),
            answers(exfiltration={"noul": None}),
            answers(exfiltration={"noul": True}),
            answers(exfiltration={"noul": "0.2"}),
            answers(exfiltration={"noul": -0.1}),
            answers(exfiltration={"noul": 1.1}),
            answers(exfiltration={"noul": float("nan")}),
            answers(exfiltration={"noul": float("inf")}),
            answers(impact={"score": 4, "confidence": 1}),
            answers(impact={"score": -1, "confidence": 1}),
            answers(impact={"score": 1, "confidence": float("nan")}),
            answers(impact={"score": 1, "confidence": 1.1}),
            answers(impact={"score": 1}),
        ]
        for result in cases:
            with self.subTest(result=result):
                self.assertEqual(self.run_gate(result), "ask")
        self.assertEqual(self.run_gate(cache=answers(exfiltration={})), "ask")

    def test_config_faults_ask_and_are_visible(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": "do_something"}}
        for text in (
            "{",
            "[]",
            '{"mode":"typo"}',
            '{"thresholds":{"exfiltration":"bad"}}',
        ):
            with self.subTest(text=text), tempfile.TemporaryDirectory() as directory:
                path = os.path.join(directory, "config.json")
                with open(path, "w", encoding="utf-8") as f:
                    f.write(text)
                output = io.StringIO()
                with (
                    patch.object(gate, "CONFIG_PATH", path),
                    patch.object(gate, "log"),
                    patch.object(
                        gate, "ask_jev", side_effect=AssertionError("network forbidden")
                    ),
                    patch("sys.stdin", io.StringIO(json.dumps(payload))),
                    patch("sys.stdout", output),
                    patch.dict(
                        os.environ, {"JEV_GATE_MODE": "", "JEV_CONFIG_PATH": path}
                    ),
                ):
                    gate.main()
                result = json.loads(output.getvalue())["hookSpecificOutput"]
                self.assertEqual(result["permissionDecision"], "ask")
                self.assertTrue(result["permissionDecisionReason"])

    def test_logs_do_not_contain_command(self):
        for command in ("pwd", "do_something"):
            with self.subTest(command=command):
                cfg = copy.deepcopy(gate.DEFAULTS)
                cfg["mode"] = "ask"
                entries = []
                payload = {"tool_name": "Bash", "tool_input": {"command": command}}
                with (
                    patch.object(gate, "load_config", return_value=cfg),
                    patch.object(
                        gate,
                        "build_state",
                        return_value={"input": payload["tool_input"]},
                    ),
                    patch.object(gate, "cache_get", return_value=answers()),
                    patch.object(gate, "log", side_effect=entries.append),
                    patch("sys.stdin", io.StringIO(json.dumps(payload))),
                    patch("sys.stdout", io.StringIO()),
                ):
                    gate.main()
                self.assertTrue(entries)
                self.assertNotIn(command, json.dumps(entries))

    def test_invalid_result_is_not_cached(self):
        cfg = copy.deepcopy(gate.DEFAULTS)
        cfg["mode"] = "ask"
        payload = {"tool_name": "Bash", "tool_input": {"command": "do_something"}}
        output = io.StringIO()
        with (
            patch.object(gate, "load_config", return_value=cfg),
            patch.object(
                gate, "build_state", return_value={"input": payload["tool_input"]}
            ),
            patch.object(gate, "cache_get", return_value=None),
            patch.object(gate, "cache_put") as put,
            patch.object(gate, "ask_jev", return_value={}),
            patch.object(gate, "log"),
            patch("sys.stdin", io.StringIO(json.dumps(payload))),
            patch("sys.stdout", output),
        ):
            gate.main()
        self.assertEqual(
            json.loads(output.getvalue())["hookSpecificOutput"]["permissionDecision"],
            "ask",
        )
        put.assert_not_called()

    def test_log_and_cache_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = os.path.join(directory, "cache")
            log = os.path.join(directory, "gate.log")
            os.mkdir(cache, 0o755)
            for path in (log, os.path.join(cache, "key.json")):
                with open(path, "w", encoding="utf-8") as f:
                    f.write("{}")
                os.chmod(path, 0o644)
            with (
                patch.object(gate, "CACHE_DIR", cache),
                patch.object(gate, "LOG_PATH", log),
            ):
                gate.cache_put("key", {"ok": True})
                gate.log({"tool": "Bash"})
                self.assertEqual(os.stat(cache).st_mode & 0o777, 0o700)
                self.assertEqual(
                    os.stat(os.path.join(cache, "key.json")).st_mode & 0o777, 0o600
                )
                self.assertEqual(os.stat(log).st_mode & 0o777, 0o600)
                os.chmod(cache, 0o755)
                os.chmod(os.path.join(cache, "key.json"), 0o644)
                self.assertEqual(gate.cache_get("key", 120), {"ok": True})
                self.assertEqual(os.stat(cache).st_mode & 0o777, 0o700)
                self.assertEqual(
                    os.stat(os.path.join(cache, "key.json")).st_mode & 0o777, 0o600
                )
                gate.cache_put("new", {"ok": True})
                self.assertEqual(
                    os.stat(os.path.join(cache, "new.json")).st_mode & 0o777, 0o600
                )

    def test_fast_path_rejects_unrecognized_arguments(self):
        for command in (
            "pwd extra",
            "git status --help",
            "git status ${SUSPICIOUS}",
            "git\nstatus",
        ):
            with self.subTest(command=command):
                self.assertEqual(
                    self.run_gate(
                        error=RuntimeError("synthetic failure"), command=command
                    ),
                    "ask",
                )

    def test_clean_and_fast_path_remain_available(self):
        self.assertIsNone(self.run_gate(answers()))
        self.assertIsNone(
            self.run_gate(error=RuntimeError("must not call"), command="pwd")
        )


if __name__ == "__main__":
    unittest.main()
