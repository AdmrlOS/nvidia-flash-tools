"""Public entrypoints and independently extracted package layout."""
import importlib
from pathlib import Path
import subprocess
import sys
import unittest


class LayoutTests(unittest.TestCase):
    def test_runtime_is_an_importable_package(self):
        module = importlib.import_module('nvidia_flash_tools.thor')
        root = Path(__file__).resolve().parent
        if root.name == 'tests':
            root = root.parent
        self.assertEqual(module.ROOT, root)
        for name in ('flow', 'vendor', 'transport', 'writer', 'orin', 'install'):
            importlib.import_module('nvidia_flash_tools.' + name)

    def test_supported_entrypoints_and_module_help(self):
        root = Path(__file__).resolve().parent
        if root.name == 'tests':
            root = root.parent
        for args in (['thor.py'], ['orin.py'], ['install.py'], ['package.py'],
                     ['-m', 'nvidia_flash_tools.thor'], ['-m', 'nvidia_flash_tools.orin']):
            result = subprocess.run([sys.executable, *args, '--help'], cwd=root,
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('usage:', result.stdout)
