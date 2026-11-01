"""Checks on release.yml: publishing gates and job permissions."""

import json
import re
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

    def test_host_creates_the_release_as_a_draft(self):
        steps = self.jobs["host"]["steps"]
        create = [s for s in steps if s.get("name") == "Create GitHub Release"]
        self.assertEqual(len(create), 1)
        self.assertIn("gh release create", create[0]["run"])
        self.assertIn("--draft", create[0]["run"])

    def test_only_tag_push_reaches_publish(self):
        job = self.jobs["publish-release"]
        self.assertIn(PUSH_TAG, job["if"])
        self.assertIn("needs.sign-update-manifest.result == 'success'", job["if"])
        self.assertIn("sign-update-manifest", job["needs"])
        self.assertIn("--draft=false", json.dumps(job["steps"]))

    def test_nothing_else_publishes_the_release(self):
        for name, job in self.jobs.items():
            text = json.dumps(job.get("steps", []))
            if name != "publish-release":
                self.assertNotIn("--draft=false", text, name)
                self.assertNotIn("release edit", text, name)

    def test_signing_secrets_appear_only_in_the_sign_step(self):
        holders = []
        for name, job in self.jobs.items():
            self.assertNotIn("secrets.FLEET_UPDATE", json.dumps(job.get("env", {})), name)
            for step in job.get("steps", []):
                if "secrets.FLEET_UPDATE" in json.dumps(step):
                    holders.append((name, step.get("name")))
        self.assertEqual(holders, [("sign-update-manifest", "Sign")])
        self.assertNotIn("secrets.FLEET_UPDATE", json.dumps(
            {k: v for k, v in self.doc.items() if k != "jobs"}
        ))

    def test_signing_runs_after_repack_and_before_upload(self):
        names = [s.get("name") for s in self.jobs["sign-update-manifest"]["steps"]]
        order = ["Repack the archives", "Write the manifest", "Sign", "Upload repacked archives, manifest and signature"]
        idx = [names.index(n) for n in order]
        self.assertEqual(idx, sorted(idx))

    def test_manifest_targets_equal_the_dist_linux_targets(self):
        scripts = WORKFLOW.parents[1] / "scripts"
        dist = (WORKFLOW.parents[2] / "dist-workspace.toml").read_text()
        listed = re.search(r"^targets = \[(.*)\]$", dist, re.M).group(1)
        linux = {t for t in re.findall(r'"([^"]+)"', listed) if "linux" in t}
        manifest = (scripts / "build_release_manifest.sh").read_text()
        named = set(re.findall(r'--target "([a-z0-9_.-]+)=', manifest))
        self.assertEqual(named, linux)
        repack = (scripts / "repack_release_archives.sh").read_text()
        repacked = set(re.search(r"for target in (.*); do", repack).group(1).split())
        self.assertEqual(repacked, linux)


if __name__ == "__main__":
    unittest.main()
