"""Protect private data directories while allowing tracked placeholders."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest

from pwnabase.storage import ResultStore

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = ('handshakes', 'complete', 'exhausted', 'no-usable-handshake', 'tool-error')


class DataDirectoryIgnoreTests(unittest.TestCase):
    def test_clone_has_placeholders_and_result_directories_become_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, clone = Path(temporary) / 'source', Path(temporary) / 'clone'
            env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
            subprocess.run(['git', 'init', '-q', str(source)], check=True, env=env)
            (source / '.gitignore').write_bytes((ROOT / '.gitignore').read_bytes())
            for directory in DIRECTORIES:
                (source / directory).mkdir()
                placeholder = (ROOT / directory / '.gitkeep').read_bytes()
                self.assertEqual(placeholder, b'')
                (source / directory / '.gitkeep').write_bytes(placeholder)
            subprocess.run(['git', 'add', '.gitignore', *[f'{d}/.gitkeep' for d in DIRECTORIES]],
                           cwd=source, check=True, env=env)
            subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-c', 'commit.gpgsign=false',
                            '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
                            'commit', '-qm', 'fixture'], cwd=source, check=True, env=env)
            subprocess.run(['git', 'clone', '-q', '--no-local', str(source), str(clone)], check=True, env=env)
            for directory in DIRECTORIES:
                self.assertTrue((clone / directory / '.gitkeep').is_file())
            # Simulate ordinary clone permissions and an existing user-owned directory.
            for directory in DIRECTORIES[1:]:
                (clone / directory).chmod(0o755)
            (clone / 'complete' / 'existing.json').write_text('{}')
            ResultStore(clone).prepare('example')
            self.assertEqual((clone / 'complete').stat().st_mode & 0o777, 0o755)
            for directory in DIRECTORIES[2:]:
                self.assertEqual((clone / directory).stat().st_mode & 0o777, 0o700)
            (clone / 'no-usable-handshake').chmod(0o755)
            (clone / 'no-usable-handshake' / '.gitkeep').write_text('user data')
            (clone / 'tool-error').chmod(0o755)
            (clone / 'tool-error' / '.gitkeep').unlink()
            (clone / 'tool-error' / '.gitkeep').mkdir()
            ResultStore(clone).prepare('example')
            for directory in ('no-usable-handshake', 'tool-error'):
                self.assertEqual((clone / directory).stat().st_mode & 0o777, 0o755)

    def test_only_root_placeholders_are_unignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
            subprocess.run(['git', 'init', '-q', temporary], check=True, env=env)
            (Path(temporary) / '.gitignore').write_bytes((ROOT / '.gitignore').read_bytes())
            for directory in DIRECTORIES:
                for path, ignored in ((f'{directory}/.gitkeep', False),
                                      (f'{directory}/example.json', True),
                                      (f'{directory}/nested/example.json', True),
                                      (f'nested/{directory}/example.json', True),
                                      (f'nested/{directory}/.gitkeep', True)):
                    with self.subTest(path=path):
                        result = subprocess.run(['git', 'check-ignore', '--no-index', '-q', path],
                                                cwd=temporary, check=False, env=env)
                        self.assertEqual(result.returncode, 0 if ignored else 1)
