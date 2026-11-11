# stack-guard — Copyright (c) 2026 House of Solance. PolyForm Noncommercial 1.0.0. Required Notice: Copyright (c) 2026 House of Solance (https://github.com/SolanceLab)
"""The daily watch catches up after a missed run: the --due gate, the schedule entries, the last-run stamp and the old-entry notice."""
import datetime
import os
import plistlib
import unittest
from unittest import mock

from test_stack_guard import Base, fake_run
import stack_guard as sg

REAL_CHECK = sg.cmd_check


def ts(h, m, s=0, day=11):
    return datetime.datetime(2026, 11, day, h, m, s).timestamp()


class SlotMaths(unittest.TestCase):
    def test_slots(self):
        self.assertEqual(sg.due_slot("03:15", ts(10, 0)), ts(3, 15))
        self.assertEqual(sg.due_slot("03:15", ts(1, 0)), ts(3, 15, day=10))
        self.assertEqual(sg.due_slot("03:15", ts(3, 15)), ts(3, 15))
        self.assertEqual(sg.due_slot("03:15", ts(3, 14, 30)), ts(3, 15))
        self.assertEqual(sg.due_slot("03:15", ts(3, 13, 0)), ts(3, 15, day=10))
        with self.assertRaises(ValueError):
            sg.due_slot("25:00", ts(10, 0))


class DueGate(Base):
    def setUp(self):
        super().setUp()
        for target, new in (("now_ts", lambda: ts(10, 0)), ("cmd_check", mock.Mock(return_value=0))):
            p = mock.patch.object(sg, target, new)
            p.start()
            self.addCleanup(p.stop)

    def stamp(self, text):
        path = sg.due_stamp_path(self.folder)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)

    def test_started_since_slot_exits_silently(self):
        sg.write_due_stamp(self.folder, ts(4, 0))
        self.assertEqual(self.run_main("check", "--due", "03:15", self.folder), (0, ""))
        sg.cmd_check.assert_not_called()

    def test_older_stamp_runs_and_restamps(self):
        sg.write_due_stamp(self.folder, ts(2, 0))
        self.assertEqual(self.run_main("check", "--due", "03:15", self.folder)[0], 0)
        self.assertEqual(sg.cmd_check.call_count, 1)
        self.assertTrue(sg.cmd_check.call_args.kwargs["due"])
        self.assertEqual(sg.read_due_stamp(self.folder), int(ts(10, 0)))

    def test_no_stamp_runs_and_stamp_lives_outside_the_folder(self):
        self.run_main("check", "--due", "03:15", self.folder)
        sg.cmd_check.assert_called_once()
        path = sg.due_stamp_path(self.folder)
        self.assertTrue(path.startswith(os.path.join(self.home, ".config", "stack-guard", "state")))
        self.assertFalse(path.startswith(os.path.abspath(self.folder)))
        self.assertEqual(sg.read_due_stamp(self.folder), int(ts(10, 0)))

    def test_bad_stamps_count_as_no_attempt(self):
        for text in ("{broken", "[]", '{"attempt": "x"}', '{"attempt": true}'):
            sg.cmd_check.reset_mock()
            self.stamp(text)
            self.run_main("check", "--due", "03:15", self.folder)
            self.assertEqual(sg.cmd_check.call_count, 1, text)

    def test_future_stamp_runs(self):
        sg.write_due_stamp(self.folder, ts(10, 0) + 3600)
        self.run_main("check", "--due", "03:15", self.folder)
        sg.cmd_check.assert_called_once()
        self.assertEqual(sg.read_due_stamp(self.folder), int(ts(10, 0)))

    def test_bad_time_exits_1(self):
        code, _ = self.run_main("check", "--due", "99:99", self.folder)
        self.assertEqual(code, 1)
        sg.cmd_check.assert_not_called()

    def test_without_due_nothing_is_stamped(self):
        self.run_main("check", self.folder)
        self.assertFalse(sg.cmd_check.call_args.kwargs["due"])
        self.assertFalse(os.path.exists(sg.config_dir("state")))

    def test_missing_folder_still_says_so(self):
        missing = os.path.join(self.tmp, "gone")
        for stamped in (True, False):
            if stamped:
                sg.write_due_stamp(missing, ts(4, 0))
            code, out = self.run_main("check", "--due", "03:15", missing)
            self.assertEqual(code, 1)
            self.assertIn("Folder not found", out)
        sg.cmd_check.assert_not_called()

    def test_real_check_runs_once_then_stays_silent(self):
        sg.cmd_check = REAL_CHECK  # the setUp patch puts the original back afterwards
        code, out = self.run_main("check", "--due", "00:00", self.folder)
        self.assertIn("Stack Guard", out)
        self.assertIn("run", out)
        self.assertEqual(self.run_main("check", "--due", "00:00", self.folder), (0, ""))


class PlanShape(Base):
    def test_darwin(self):
        plan = sg.watch_plan("darwin", self.folder, "07:30")
        pl = plistlib.loads(plan["content"])
        self.assertIs(pl["RunAtLoad"], True)
        self.assertEqual(pl["StartCalendarInterval"], {"Hour": 7, "Minute": 30})
        args = pl["ProgramArguments"]
        self.assertEqual(args[args.index("--due") + 1], "07:30")
        self.assertLess(args.index("--notify"), args.index("--due"))
        self.assertEqual(args[-1], os.path.abspath(self.folder))

    def test_linux(self):
        plan = sg.watch_plan("linux", self.folder, "07:30")
        mark = sg.CRON_MARK + sg.folder_hash(self.folder)
        self.assertTrue(plan["line"].startswith("30 * * * * "))
        self.assertIn("--due 07:30", plan["line"])
        self.assertTrue(plan["line"].endswith(mark))
        self.assertEqual(plan["marker"], mark)

    def test_windows_is_unchanged(self):
        with mock.patch.object(sg, "platform_name", lambda: "windows"):
            plan = sg.watch_plan("windows", self.folder, "07:30")
        self.assertNotIn("--due", plan["cmd_text"])
        self.assertNotIn("--due", plan["show"])
        self.assertIn("/SC", plan["install"][0])
        self.assertIn("DAILY", plan["install"][0])


class InstallStamp(Base):
    def setUp(self):
        super().setUp()
        self.now = [ts(10, 0)]
        for target, new in (("now_ts", lambda: self.now[0]), ("run_cmd", lambda a, **k: (0, ""))):
            p = mock.patch.object(sg, target, new)
            p.start()
            self.addCleanup(p.stop)

    def plan(self, plat):
        return sg.watch_plan(plat, self.folder, "07:30")

    def test_install_stamps_once_per_plat(self):
        for plat in ("darwin", "linux"):
            with mock.patch.object(sg, "platform_name", lambda p=plat: p):
                os.path.lexists(sg.due_stamp_path(self.folder)) and os.remove(sg.due_stamp_path(self.folder))
                sg.apply_plan(self.plan(plat), False)
                self.assertEqual(sg.read_due_stamp(self.folder), int(ts(10, 0)), plat)
                sg.write_due_stamp(self.folder, 12345)
                sg.apply_plan(self.plan(plat), False)
                self.assertEqual(sg.read_due_stamp(self.folder), 12345.0, plat)

    def test_remove_without_stamp_creates_none(self):
        sg.apply_plan(self.plan("darwin"), True)
        self.assertFalse(os.path.lexists(sg.due_stamp_path(self.folder)))

    def test_windows_install_makes_no_stamp(self):
        with mock.patch.object(sg, "platform_name", lambda: "windows"):
            sg.apply_plan(self.plan("windows"), False)
        self.assertFalse(os.path.lexists(sg.due_stamp_path(self.folder)))

    def test_remove_drops_stamp_and_reinstall_starts_fresh(self):
        sg.apply_plan(self.plan("darwin"), False)
        self.assertIsNotNone(sg.read_due_stamp(self.folder))
        self.assertTrue(sg.apply_plan(self.plan("darwin"), True))
        self.assertIsNone(sg.read_due_stamp(self.folder))
        self.now[0] = ts(15, 0)
        sg.apply_plan(self.plan("darwin"), False)
        self.assertEqual(sg.read_due_stamp(self.folder), int(ts(15, 0)))

    def test_failed_removal_keeps_stamp(self):
        sg.apply_plan(self.plan("darwin"), False)
        with mock.patch.object(sg, "run_cmd", lambda a, **k: (1, "")):
            self.assertFalse(sg.apply_plan(self.plan("darwin"), True))
        self.assertIsNotNone(sg.read_due_stamp(self.folder))

    def test_remove_all_clears_stamps_and_keeps_other_files(self):
        sg.apply_plan(self.plan("darwin"), False)
        other = os.path.join(self.tmp, "other")
        os.makedirs(other)
        sg.write_due_stamp(other, ts(4, 0))
        keep = os.path.join(sg.config_dir("state"), "notes.txt")
        with open(keep, "w", encoding="utf-8") as fh:
            fh.write("mine")
        with mock.patch("sys.stdout"):
            self.assertEqual(sg.cmd_watch_remove(self.folder, True), 0)
        self.assertIsNone(sg.read_due_stamp(self.folder))
        self.assertIsNone(sg.read_due_stamp(other))
        self.assertTrue(os.path.exists(keep))


class OldEntryNotice(Base):
    def old_plist(self):
        plan = sg.watch_plan("darwin", self.folder, "07:30")
        pl = plistlib.loads(plan["content"])
        args = pl["ProgramArguments"]
        i = args.index("--due")
        del args[i:i + 2]
        pl.pop("RunAtLoad", None)
        os.makedirs(os.path.dirname(plan["file"]), exist_ok=True)
        with open(plan["file"], "wb") as fh:
            fh.write(plistlib.dumps(pl))
        return plan

    def cron_run(self, text):
        def run(args, input_text=None, timeout=30, cwd=None, stderr_out=None, env=None):
            if os.path.basename(str(args[0])) == "crontab" and list(args[1:]) == ["-l"]:
                return 0, text
            return fake_run(args, input_text, timeout, cwd, stderr_out, env)
        return run

    def seen(self, *args):
        code, out = self.run_main(*args)
        return out, self.report().split("## New since")[0], str(sg.notify_desktop.call_args_list)

    def test_no_entry_no_notice(self):
        self.assertFalse(sg.old_watch_entry(self.folder))
        out, rep, note = self.seen("check", self.folder, "--notify")
        for where in (out, rep, note):
            self.assertNotIn(sg.OLD_WATCH_NOTE, where)

    def test_old_plist_gives_notice_in_output_and_report_only(self):
        self.old_plist()
        self.assertTrue(sg.old_watch_entry(self.folder))
        out, rep, note = self.seen("check", self.folder, "--notify")
        self.assertIn(sg.OLD_WATCH_NOTE, out)
        self.assertIn(sg.OLD_WATCH_NOTE, rep)
        self.assertNotIn(sg.OLD_WATCH_NOTE, note)

    def test_new_plist_gives_no_notice(self):
        plan = sg.watch_plan("darwin", self.folder, "07:30")
        os.makedirs(os.path.dirname(plan["file"]), exist_ok=True)
        with open(plan["file"], "wb") as fh:
            fh.write(plan["content"])
        self.assertFalse(sg.old_watch_entry(self.folder))
        out, rep, _ = self.seen("check", self.folder, "--notify")
        self.assertNotIn(sg.OLD_WATCH_NOTE, out + rep)

    def test_old_plist_with_due_run_gives_no_notice(self):
        self.old_plist()
        out, rep, _ = self.seen("check", "--due", "00:00", "--notify", self.folder)
        self.assertNotIn(sg.OLD_WATCH_NOTE, out + rep)

    def test_old_plist_without_notify_gives_no_notice(self):
        self.old_plist()
        out, rep, _ = self.seen("check", self.folder)
        self.assertNotIn(sg.OLD_WATCH_NOTE, out + rep)

    def test_broken_plist_is_no_entry(self):
        plan = sg.watch_plan("darwin", self.folder, "07:30")
        os.makedirs(os.path.dirname(plan["file"]), exist_ok=True)
        with open(plan["file"], "wb") as fh:
            fh.write(b"not a plist")
        self.assertFalse(sg.old_watch_entry(self.folder))
        self.assertEqual(self.run_main("check", self.folder, "--notify")[0], 0)

    def test_other_folders_old_plist_is_ignored(self):
        other = os.path.join(self.tmp, "other")
        os.makedirs(other)
        plan = sg.watch_plan("darwin", other, "07:30")
        os.makedirs(os.path.dirname(plan["file"]), exist_ok=True)
        with open(plan["file"], "wb") as fh:
            fh.write(plan["content"].replace(b"--due", b"--xxx"))
        self.assertFalse(sg.old_watch_entry(self.folder))

    def test_linux_crontab(self):
        new_line = sg.watch_plan("linux", self.folder, "07:30")["line"]
        old_line = new_line.replace(" --due 07:30", "")
        self.assertNotIn("--due", old_line)
        with mock.patch.object(sg, "platform_name", lambda: "linux"):
            with mock.patch.object(sg, "run_cmd", self.cron_run(old_line + "\n")):
                self.assertTrue(sg.old_watch_entry(self.folder))
                out, rep, note = self.seen("check", self.folder, "--notify")
                self.assertIn(sg.OLD_WATCH_NOTE, out)
                self.assertIn(sg.OLD_WATCH_NOTE, rep)
                self.assertNotIn(sg.OLD_WATCH_NOTE, note)
            for text in (new_line + "\n", "", "# " + old_line + "\n"):
                with mock.patch.object(sg, "run_cmd", self.cron_run(text)):
                    self.assertFalse(sg.old_watch_entry(self.folder), text)
            self.assertFalse(sg.old_watch_entry(self.folder))  # crontab missing: fake_run gives 127

    def test_windows_never_reports(self):
        self.old_plist()
        with mock.patch.object(sg, "platform_name", lambda: "windows"):
            self.assertFalse(sg.old_watch_entry(self.folder))

    def test_note_needs_notify_and_no_due(self):
        self.old_plist()
        self.assertIsNone(sg.old_watch_note(True, True, self.folder))
        self.assertIsNone(sg.old_watch_note(False, False, self.folder))
        self.assertEqual(sg.old_watch_note(True, False, self.folder), sg.OLD_WATCH_NOTE)


if __name__ == "__main__":
    unittest.main()
