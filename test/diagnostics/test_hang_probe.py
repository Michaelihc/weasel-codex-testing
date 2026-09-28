"""Check that the command line probe can capture a usable Windows dump."""

import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))
from hang_probe import capture_dump


@unittest.skipUnless(sys.platform == "win32", "Windows dump API required")
class HangProbeTests(unittest.TestCase):
    def test_capture_dump_of_current_process(self):
        with TemporaryDirectory() as folder:
            dump = Path(folder) / "self.dmp"
            capture_dump(os.getpid(), dump)
            with dump.open("rb") as stream:
                self.assertEqual(stream.read(4), b"MDMP")
            self.assertGreater(dump.stat().st_size, 4096)


if __name__ == "__main__":
    unittest.main()
