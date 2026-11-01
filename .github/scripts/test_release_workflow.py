"""Checks on release.yml: publishing gates and job permissions."""

import json
import pathlib
import subprocess
import unittest

WORKFLOW = pathlib.Path(__file__).resolve().parents[1] / "workflows" / "release.yml"
PUSH_TAG = "github.event_name == 'push' && github.ref_type == 'tag'"


def load():
    out = subprocess.run(
        [
            "ruby",
            "-ryaml",
            "-rjson",
            "-e",
            "puts JSON.generate(YAML.load_file(ARGV[0]))",
            str(WORKFLOW),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return json.loads(out.stdout)


class ReleaseWorkflow(unittest.TestCase):
    def setUp(self):
        self.doc = load()
        self.jobs = self.doc["jobs"]

    def test_signing_job_runs_only_on_a_tag_push(self):
        cond = self.jobs["sign-update-manifest"]["if"]
        self.assertIn(PUSH_TAG, cond)

    def test_publishing_output_excludes_dispatch(self):
        publishing = self.jobs["plan"]["outputs"]["publishing"]
        self.assertIn(PUSH_TAG, publishing)

    def test_host_and_signing_depend_on_publishing(self):
        for name in ("host", "sign-update-manifest"):
            cond = self.jobs[name]["if"]
            self.assertIn("needs.plan.outputs.publishing == 'true'", cond)

    def test_dry_run_job_is_read_only(self):
        perms = self.jobs["update-manifest-dry-run"].get("permissions")
        self.assertEqual(perms, {"contents": "read"})

    def test_signing_job_declares_its_own_permissions(self):
        perms = self.jobs["sign-update-manifest"].get("permissions")
        self.assertEqual(perms, {"contents": "write"})


if __name__ == "__main__":
    unittest.main()
