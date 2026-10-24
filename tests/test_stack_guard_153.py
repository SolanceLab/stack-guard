# stack-guard — Copyright (c) 2026 House of Solance. MIT License, see LICENSE. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""Offline tests for 1.5.3: a private Python index set for the whole computer, and files that point outside the scanned folder.
Run: python3 -m unittest discover -s tests -v"""
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

from test_stack_guard import Base, symlink
import stack_guard as sg

HOST = "corp-mirror.example"  # stands in for a private host; it must never appear in any output


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)


class ComputerWidePrivateIndex(Base):
    def pypi_targets(self, stats=None):
        sg._global_index = None
        return [t for t in sg.collect_targets(sg.build_inventory(self.folder), stats) if t["ecosystem"] == "PyPI"]

    def test_nothing_set_names_are_still_checked(self):
        self.assertTrue(self.pypi_targets())

    def test_private_env_vars_keep_pypi_names_home(self):
        for name, value in (("PIP_INDEX_URL", "https://%s/simple" % HOST), ("PIP_EXTRA_INDEX_URL", "https://u:p@%s/s" % HOST),
                            ("PIP_FIND_LINKS", "/srv/wheels"), ("PIP_NO_INDEX", "1"), ("UV_INDEX_URL", "https://%s/s" % HOST),
                            ("UV_INDEX", "corp=https://%s/s" % HOST), ("UV_DEFAULT_INDEX", "https://%s/s" % HOST),
                            ("POETRY_REPOSITORIES_CORP_URL", "https://%s/s" % HOST), ("POETRY_SOURCE_CORP", "https://%s/s" % HOST)):
            with mock.patch.dict(os.environ, {name: value}):
                stats = {}
                self.assertEqual(self.pypi_targets(stats), [], name)
                self.assertTrue(stats["private"] and stats["computer_index"], name)

    def test_env_pointing_at_pypi_changes_nothing(self):
        with mock.patch.dict(os.environ, {"PIP_INDEX_URL": "https://pypi.org/simple", "UV_INDEX_URL": "https://pypi.org/simple/"}):
            self.assertTrue(self.pypi_targets())

    def test_config_files_are_read(self):
        for rel, text in ((".config/pip/pip.conf", "[global]\nextra-index-url = https://%s/simple\n" % HOST),
                          (".pip/pip.conf", "[global]\nindex_url = https://%s/simple\n" % HOST),
                          (".config/uv/uv.toml", '[[index]]\nname = "corp"\nurl = "https://%s/simple"\n' % HOST),
                          (".config/uv/uv.toml", 'no-index = true\n'),
                          (".config/uv/uv.toml", 'default-index = "https://%s/simple"\n' % HOST),
                          (".config/pypoetry/config.toml", '[repositories.corp]\nurl = "https://%s/simple"\n' % HOST),
                          (".config/pip/pip.conf", "[global]\nfind-links =\n    https://pypi.org/simple\n    https://%s/w\n" % HOST)):
            path = os.path.join(self.home, rel)
            write(path, text)
            self.assertEqual(self.pypi_targets(), [], rel)
            os.remove(path)

    def test_config_pointing_at_pypi_changes_nothing(self):
        write(os.path.join(self.home, ".config", "pip", "pip.conf"), "[global]\nindex-url = https://pypi.org/simple\ntimeout = 5\n")
        self.assertTrue(self.pypi_targets())

    def test_moved_config_folders_are_read(self):
        xdg = os.path.join(self.tmp, "xdg-home")
        xdg_dirs = os.path.join(self.tmp, "xdg-sys")
        for env, rel, text in ((("XDG_CONFIG_HOME", xdg), "pip/pip.conf", "[global]\nindex-url = https://%s/simple\n" % HOST),
                               (("XDG_CONFIG_HOME", xdg), "uv/uv.toml", 'default-index = "https://%s/simple"\n' % HOST),
                               (("XDG_CONFIG_DIRS", xdg_dirs), "pip/pip.conf", "[global]\nindex-url = https://%s/simple\n" % HOST)):
            path = os.path.join(env[1], rel)
            write(path, text)
            with mock.patch.dict(os.environ, {env[0]: env[1]}):
                self.assertEqual(self.pypi_targets(), [], (env[0], rel))
            os.remove(path)

    def test_pip_config_file_env_is_read(self):
        conf = os.path.join(self.tmp, "elsewhere.conf")
        write(conf, "[global]\nindex-url = https://%s/simple\n" % HOST)
        with mock.patch.dict(os.environ, {"PIP_CONFIG_FILE": conf}):
            self.assertEqual(self.pypi_targets(), [])

    def test_public_custom_config_file_still_gets_checked(self):
        conf = os.path.join(self.tmp, "public.conf")
        write(conf, "[global]\nindex-url = https://pypi.org/simple\n")
        with mock.patch.dict(os.environ, {"PIP_CONFIG_FILE": conf}):
            self.assertTrue(self.pypi_targets())
        with mock.patch.dict(os.environ, {"UV_CONFIG_FILE": os.path.join(self.tmp, "missing.toml")}):
            self.assertEqual(self.pypi_targets(), [])  # unreadable stays private

    def test_the_address_never_appears_in_any_output(self):
        write(os.path.join(self.home, ".config", "pip", "pip.conf"), "[global]\nindex-url = https://user:pw@%s/simple\n" % HOST)
        with mock.patch.dict(os.environ, {"PIP_EXTRA_INDEX_URL": "https://%s/other" % HOST}):
            code, out = self.run_main("check", self.folder, "--notify")
            texts = [out, self.report(), json.dumps(sg.build_inventory(self.folder))]
            for dirpath, _, names in os.walk(os.path.join(self.folder, ".stack-guard")):
                for n in names:
                    with open(os.path.join(dirpath, n), encoding="utf-8", errors="replace") as fh:
                        texts.append(fh.read())
        for t in texts:
            self.assertNotIn(HOST, t)
            self.assertNotIn("user:pw", t)
        self.assertIn("a private Python index is set on this computer", self.report())


class ShortcutsOutOfTheFolder(Base):
    def test_linked_folder_into_a_skipped_folder_is_reported(self):
        hidden = os.path.join(self.folder, ".cache", "proj")
        os.makedirs(hidden)
        with open(os.path.join(hidden, "requirements.txt"), "w") as fh:
            fh.write("hidden-pkg==1.0.0\n")
        symlink(hidden, os.path.join(self.folder, "alias2"))
        inv = sg.build_inventory(self.folder)
        self.assertTrue([x for x in inv["unreadable"] if x.startswith("alias2")])

    def test_linked_folder_inside_the_root_is_scanned_once_at_its_real_place(self):
        real = os.path.join(self.folder, "realproj")
        os.makedirs(real)
        with open(os.path.join(real, "requirements.txt"), "w") as fh:
            fh.write("inside-linked-pkg==1.0.0\n")
        symlink(real, os.path.join(self.folder, "alias"))
        inv = sg.build_inventory(self.folder)
        names = [p["name"] for pr in inv["projects"] for p in pr["packages"] if p["name"] == "inside-linked-pkg"]
        self.assertEqual(len(names), 1)
        self.assertFalse([x for x in inv["unreadable"] if x.startswith("alias")])

    def setUp(self):
        super().setUp()
        self.outside = os.path.join(self.tmp, "elsewhere")
        write(os.path.join(self.outside, "reqs.txt"), "outsidepkg==1.0.0\n")
        self.req = os.path.join(self.folder, "api", "requirements.txt")
        os.remove(self.req)

    def api_packages(self, inv):
        return {x["name"] for p in inv["projects"] if p["path"] == "api" for x in p["packages"]}

    def test_link_to_a_file_outside_is_not_read_and_is_noted(self):
        symlink(os.path.join(self.outside, "reqs.txt"), self.req)
        inv = sg.build_inventory(self.folder)
        self.assertNotIn("outsidepkg", self.api_packages(inv))
        rep = sg.make_report(inv, [], [], True)
        self.assertIn("`api/requirements.txt` points outside the scanned folder, so it was not read.", rep["not_checked"])
        self.assertIn("points outside the scanned folder", sg.render_inventory(inv))

    def test_link_to_a_file_inside_is_read(self):
        write(os.path.join(self.folder, "api", "real-reqs.txt"), "insidepkg==1.0.0\n")
        symlink(os.path.join(self.folder, "api", "real-reqs.txt"), self.req)
        inv = sg.build_inventory(self.folder)
        self.assertIn("insidepkg", self.api_packages(inv))
        self.assertEqual(inv["outside"], [])

    def test_linked_folder_outside_is_not_walked(self):
        write(os.path.join(self.outside, "lib", "requirements.txt"), "walkedpkg==1.0.0\n")
        symlink(os.path.join(self.outside, "lib"), os.path.join(self.folder, "lib"))
        inv = sg.build_inventory(self.folder)
        self.assertNotIn("lib", [p["path"] for p in inv["projects"]])

    def test_project_mcp_file_linked_outside_is_not_read(self):
        write(os.path.join(self.outside, "mcp.json"), json.dumps({"mcpServers": {"x": {"command": "npx", "args": ["-y", "outside-mcp"]}}}))
        mcp = os.path.join(self.folder, ".mcp.json")
        if os.path.lexists(mcp):
            os.remove(mcp)
        symlink(os.path.join(self.outside, "mcp.json"), mcp)
        inv = sg.build_inventory(self.folder)
        self.assertNotIn("outside-mcp", json.dumps(inv["mcp"]))
        self.assertEqual(inv["outside"], [".mcp.json"])


class FalseValuedNoIndex(ComputerWidePrivateIndex):
    """PIP_NO_INDEX read as a boolean: 0/false/no/off do not make the computer private."""

    def test_false_values_keep_names_checked(self):
        for value in ("0", "false", "No", "OFF"):
            with mock.patch.dict(os.environ, {"PIP_NO_INDEX": value}):
                self.assertTrue(self.pypi_targets(), value)

    def test_true_values_keep_names_home(self):
        for value in ("1", "true", "yes", "on", ""):  # an empty value is not false
            with mock.patch.dict(os.environ, {"PIP_NO_INDEX": value}):
                self.assertEqual(self.pypi_targets(), [], value)


class MoreIndexSources(ComputerWidePrivateIndex):
    """1.5.5: project uv.toml / poetry.toml and more computer-wide locations count as a private index."""

    def project_targets(self):
        return [t for t in self.pypi_targets() if t["project"] == "api"]  # the project with the requirements file

    def test_project_uv_and_poetry_files(self):
        for fn, text in (("uv.toml", '[[index]]\nurl = "https://%s/simple"\n' % HOST),
                         ("uv.toml", 'default-index = "https://%s/simple"\n' % HOST),
                         ("poetry.toml", '[repositories.corp]\nurl = "https://%s/simple"\n' % HOST)):
            write(os.path.join(self.folder, "api", fn), text)
            self.assertEqual(self.project_targets(), [], fn)
            os.remove(os.path.join(self.folder, "api", fn))
        write(os.path.join(self.folder, "api", "poetry.toml"), "[virtualenvs]\nin-project = true\n")
        self.assertTrue(self.project_targets())

    def test_root_config_only_folder_covers_nested_projects(self):
        write(os.path.join(self.folder, "uv.toml"), 'default-index = "https://%s/simple"\n' % HOST)  # no packages at the root itself
        self.assertEqual(self.project_targets(), [])
        inv = sg.build_inventory(self.folder)
        self.assertTrue(all(p["private_index"] for p in inv["projects"]))
        self.assertNotIn(HOST, json.dumps(inv))

    def test_more_computer_wide_locations(self):
        base = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, base, True)
        private = '[[index]]\nurl = "https://%s/simple"\n' % HOST
        pip_private = "[global]\nindex-url = https://%s/simple\n" % HOST
        for env, rel, text in (("APPDATA", "uv/uv.toml", private),
                               ("APPDATA", "pypoetry/config.toml", '[repositories.corp]\nurl = "https://%s/s"\n' % HOST),
                               ("PROGRAMDATA", "pip/pip.ini", pip_private),
                               ("PROGRAMDATA", "uv/uv.toml", private),
                               ("VIRTUAL_ENV", "pip.ini", pip_private),
                               ("VIRTUAL_ENV", "pip.conf", pip_private),
                               ("POETRY_CONFIG_DIR", "config.toml", '[repositories.corp]\nurl = "https://%s/s"\n' % HOST)):
            root = os.path.join(base, env)
            write(os.path.join(root, *rel.split("/")), text)
            with mock.patch.dict(os.environ, {env: root}):
                self.assertEqual(self.pypi_targets(), [], (env, rel))
            shutil.rmtree(root)

    def test_empty_no_index_is_private(self):
        with mock.patch.dict(os.environ, {"PIP_NO_INDEX": ""}):
            self.assertEqual(self.pypi_targets(), [])
        with mock.patch.dict(os.environ, {"UV_NO_INDEX": ""}):
            self.assertEqual(self.pypi_targets(), [])


if __name__ == "__main__":
    unittest.main()
