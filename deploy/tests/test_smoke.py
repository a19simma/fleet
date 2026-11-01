"""Tests for smoke.sh driven against a fake fleet executable."""

import os
import pathlib
import stat
import subprocess
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE.parent / "smoke.sh"
JOB_ID = "01JABCDEFGHJKMNPQRSTVWXYZ0"
TOKEN = "tok-secret-" + "z9q8w7e6"
SERVER = "https://example.invalid:1"

FAKE_FLEET = """#!/bin/sh
printf '%s\\n' "$*" >> "$FAKE_DIR/argv.log"
case "$1" in
submit)
  printf '%s\\n' "$FAKE_JOB_ID"
  ;;
status)
  n=$(cat "$FAKE_DIR/polls" 2>/dev/null || echo 0)
  n=$((n + 1))
  echo "$n" > "$FAKE_DIR/polls"
  seq_file="$FAKE_DIR/states"
  line=$(sed -n "${n}p" "$seq_file")
  [ -n "$line" ] || line=$(tail -n 1 "$seq_file")
  printf 'id: %s\\nstate: %s\\nphase: p\\nbranch: secret-branch\\nerror: boom\\n' "$FAKE_JOB_ID" "$line"
  ;;
cancel)
  echo "$2 CANCELLED"
  ;;
logs)
  if [ -n "${FAKE_EVIL_LOGS:-}" ]; then
    printf 'keep\\033[31mred\\033[0m\\r\\033]0;x\\007\\302\\205\\200tail\\nsecond line\\n'
    exit 0
  fi
  printf 'chmod: noisy\\nline one\\n'
  head -c 6000 /dev/zero | tr '\\0' 'x'
  echo
  ;;
esac
exit 0
"""

FAKE_SLEEP = """#!/bin/sh
echo "$1" >> "$FAKE_DIR/sleeps.log"
exit 0
"""


def write_exec(path, text):
    path.write_text(text)
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class Run:
    def __init__(self, states, env=None, drop=(), job_id=JOB_ID, flags=()):
        self.states = states
        self.extra = env or {}
        self.drop = drop
        self.job_id = job_id
        self.flags = list(flags)

    def __enter__(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        write_exec(self.dir / "fleet", FAKE_FLEET)
        bindir = self.dir / "bin"
        bindir.mkdir()
        write_exec(bindir / "sleep", FAKE_SLEEP)
        (self.dir / "states").write_text("\n".join(self.states) + "\n")
        env = {
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "FAKE_DIR": str(self.dir),
            "FAKE_JOB_ID": self.job_id,
            "FLEET_BIN": str(self.dir / "fleet"),
            "FLEET_SERVER_URL": SERVER,
            "FLEET_CLIENT_TOKEN": TOKEN,
            "SMOKE_REPO": "owner/repo",
        }
        env.update(self.extra)
        for key in self.drop:
            env.pop(key, None)
        self.proc = subprocess.run(
            ["sh", *self.flags, str(SCRIPT)],
            env=env,
            capture_output=True,
            timeout=60,
        )
        self.raw_stderr = self.proc.stderr
        self.proc.stdout = self.proc.stdout.decode("utf-8", "surrogateescape")
        self.proc.stderr = self.proc.stderr.decode("utf-8", "surrogateescape")
        return self

    def __exit__(self, *exc):
        self.tmp.cleanup()

    @property
    def argv(self):
        path = self.dir / "argv.log"
        return path.read_text() if path.exists() else ""

    @property
    def out(self):
        return self.proc.stdout + self.proc.stderr

    def calls(self, verb):
        return [l for l in self.argv.splitlines() if l.split(" ")[0] == verb]


class Refusal(unittest.TestCase):
    def test_unset_server(self):
        with Run(["SUCCEEDED"], drop=("FLEET_SERVER_URL",)) as r:
            self.assertEqual(r.proc.returncode, 2)
            self.assertIn("FLEET_SERVER_URL", r.out)
            self.assertEqual(r.argv, "")

    def test_unset_token(self):
        with Run(["SUCCEEDED"], drop=("FLEET_CLIENT_TOKEN",)) as r:
            self.assertEqual(r.proc.returncode, 2)
            self.assertIn("FLEET_CLIENT_TOKEN", r.out)
            self.assertEqual(r.argv, "")

    def test_empty_token(self):
        with Run(["SUCCEEDED"], env={"FLEET_CLIENT_TOKEN": ""}) as r:
            self.assertEqual(r.proc.returncode, 2)
            self.assertEqual(r.argv, "")

    def test_unset_repo(self):
        with Run(["SUCCEEDED"], drop=("SMOKE_REPO",)) as r:
            self.assertEqual(r.proc.returncode, 2)
            self.assertIn("SMOKE_REPO", r.out)
            self.assertEqual(r.argv, "")

    def test_bad_agent_names(self):
        for bad in ["Claude", "a b", "x;y", "", "a" * 33, "../x"]:
            with self.subTest(agent=bad):
                with Run(["SUCCEEDED"], env={"SMOKE_AGENT": bad}) as r:
                    self.assertEqual(r.proc.returncode, 2)
                    self.assertEqual(r.argv, "")

    def test_bad_deadlines(self):
        for bad in ["9", "3601", "abc", "1.5", "-5", ""]:
            with self.subTest(deadline=bad):
                with Run(["SUCCEEDED"], env={"SMOKE_DEADLINE_SECS": bad}) as r:
                    self.assertEqual(r.proc.returncode, 2)
                    self.assertEqual(r.argv, "")

    def test_bad_job_ids(self):
        for bad in ["short", JOB_ID.lower(), JOB_ID + "A", "x" * 26, "../../etc"]:
            with self.subTest(job_id=bad):
                with Run(["SUCCEEDED"], job_id=bad) as r:
                    self.assertEqual(r.proc.returncode, 7)
                    self.assertEqual(r.calls("status"), [])


class Submit(unittest.TestCase):
    def test_argv_shape(self):
        with Run(["SUCCEEDED"], env={"SMOKE_AGENT": "kimi", "SMOKE_BASE": "dev"}) as r:
            sub = r.calls("submit")[0]
            self.assertIn("--no-pr", sub)
            self.assertIn("--agent kimi", sub)
            self.assertIn("--repo owner/repo", sub)
            self.assertIn("--base dev", sub)
            self.assertIn("--idempotency-key ", sub)

    def test_defaults(self):
        with Run(["SUCCEEDED"]) as r:
            sub = r.calls("submit")[0]
            self.assertIn("--agent claude", sub)
            self.assertIn("--base main", sub)

    def test_fresh_key_per_run(self):
        keys = []
        for _ in range(2):
            with Run(["SUCCEEDED"]) as r:
                sub = r.calls("submit")[0].split(" ")
                keys.append(sub[sub.index("--idempotency-key") + 1])
        self.assertNotEqual(keys[0], keys[1])
        self.assertTrue(all(len(k) >= 16 for k in keys))


class States(unittest.TestCase):
    def test_succeeded(self):
        with Run(["QUEUED", "RUNNING", "RUNNING", "SUCCEEDED"]) as r:
            self.assertEqual(r.proc.returncode, 0)
            self.assertEqual(len(r.calls("status")), 4)
            self.assertEqual(r.calls("logs"), [])
            self.assertEqual(r.calls("cancel"), [])

    def test_failed(self):
        with Run(["RUNNING", "FAILED"]) as r:
            self.assertEqual(r.proc.returncode, 3)
            self.assertEqual(len(r.calls("logs")), 1)
            self.assertEqual(r.calls("cancel"), [])

    def test_cancelled(self):
        with Run(["CANCELLED"]) as r:
            self.assertEqual(r.proc.returncode, 4)
            self.assertEqual(len(r.calls("logs")), 1)

    def test_lost_is_unknown(self):
        with Run(["RUNNING", "LOST"]) as r:
            self.assertEqual(r.proc.returncode, 6)
            self.assertEqual(len(r.calls("logs")), 1)

    def test_unknown_states(self):
        for state in ["UNKNOWN", "PENDING", "WEIRD", ""]:
            with self.subTest(state=state):
                with Run([state]) as r:
                    self.assertEqual(r.proc.returncode, 6)

    def test_waiting_states_sleep(self):
        with Run(["QUEUED", "RUNNING", "SUCCEEDED"]) as r:
            sleeps = (r.dir / "sleeps.log").read_text().split()
            self.assertEqual(sleeps, ["5", "5"])


class Deadline(unittest.TestCase):
    def test_timeout_cancels(self):
        with Run(["RUNNING"], env={"SMOKE_DEADLINE_SECS": "10"}) as r:
            self.assertEqual(r.proc.returncode, 5)
            self.assertEqual(r.calls("cancel"), [f"cancel {JOB_ID}"])
            self.assertEqual(len(r.calls("status")), 2)
            self.assertEqual(len(r.calls("logs")), 1)

    def test_terminal_on_last_poll_is_not_timeout(self):
        with Run(["RUNNING", "SUCCEEDED"], env={"SMOKE_DEADLINE_SECS": "10"}) as r:
            self.assertEqual(r.proc.returncode, 0)
            self.assertEqual(r.calls("cancel"), [])


class Output(unittest.TestCase):
    def test_token_never_leaks(self):
        for states, env in [
            (["SUCCEEDED"], {}),
            (["FAILED"], {}),
            (["RUNNING"], {"SMOKE_DEADLINE_SECS": "10"}),
        ]:
            with Run(states, env=env) as r:
                self.assertNotIn(TOKEN, r.out)
                self.assertNotIn(TOKEN, r.argv)
                self.assertNotIn(SERVER, r.argv)

    def test_token_absent_under_xtrace(self):
        cases = [
            (["SUCCEEDED"], {}, ()),
            (["FAILED"], {}, ()),
            (["RUNNING"], {"SMOKE_DEADLINE_SECS": "10"}, ()),
            (["SUCCEEDED"], {"SMOKE_AGENT": "BAD AGENT"}, ()),
            (["SUCCEEDED"], {}, ("SMOKE_REPO",)),
            (["SUCCEEDED"], {}, ("FLEET_SERVER_URL",)),
        ]
        for states, env, drop in cases:
            with Run(states, env=env, drop=drop, flags=["-x"]) as r:
                self.assertIn("+", r.proc.stderr)
                self.assertNotIn(TOKEN, r.proc.stdout)
                self.assertNotIn(TOKEN, r.proc.stderr)

    def test_token_absent_under_xtrace_when_token_refused(self):
        with Run(["SUCCEEDED"], env={"FLEET_CLIENT_TOKEN": ""}, flags=["-x"]) as r:
            self.assertEqual(r.proc.returncode, 2)
            self.assertNotIn(TOKEN, r.out)

    def test_status_fields_limited(self):
        with Run(["RUNNING", "SUCCEEDED"]) as r:
            self.assertNotIn("secret-branch", r.out)
            self.assertIn("SUCCEEDED", r.out)

    def test_logs_filtered_and_capped_on_failure(self):
        with Run(["FAILED"]) as r:
            self.assertNotIn("chmod:", r.out)
            self.assertIn("line one", r.out)
            self.assertLessEqual(r.out.count("x"), 4000)
            self.assertLessEqual(len(r.out), 4000 + 2000)

    def test_logs_control_characters_removed(self):
        with Run(["FAILED"], env={"FAKE_EVIL_LOGS": "1"}) as r:
            self.assertEqual(r.proc.returncode, 3)
            raw = r.raw_stderr
            for bad in (b"\x1b", b"\r", b"\x07", b"\xc2", b"\x85", b"\x80"):
                self.assertNotIn(bad, raw)
            self.assertIn("keep", r.proc.stderr)
            self.assertIn("tail\nsecond line\n", r.proc.stderr)

    def test_logs_silent_on_success(self):
        with Run(["SUCCEEDED"]) as r:
            self.assertNotIn("line one", r.out)


if __name__ == "__main__":
    unittest.main()
