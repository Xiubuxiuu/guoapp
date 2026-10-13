import plistlib
import tempfile
import unittest
import zipfile
from pathlib import Path

from app_build import BuildVariant
from validate_ios import validate_ipa


class IpaStructureTests(unittest.TestCase):
    def check_rejected(self, entries, expected):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'application.ipa'
            with zipfile.ZipFile(package, 'w') as archive:
                for name, data in entries.items():
                    archive.writestr(name, data)
            with self.assertRaisesRegex(ValueError, expected):
                validate_ipa(package, BuildVariant(True), Path(directory) / 'validation.json')

    def metadata(self):
        return {'CFBundleDisplayName': '真果鉴', 'CFBundleName': 'zhenguojian',
                'CFBundleIdentifier': 'com.duanju.duanjuApp', 'CFBundlePackageType': 'APPL',
                'CFBundleSupportedPlatforms': ['iPhoneOS'], 'MinimumOSVersion': '15.1'}

    def test_payload_directory_is_required(self):
        self.check_rejected({'Runner.app/Info.plist': plistlib.dumps(self.metadata())}, 'Payload/Runner.app')

    def test_path_traversal_is_rejected(self):
        self.check_rejected({'Payload/Runner.app/Info.plist': plistlib.dumps(self.metadata()),
                             '../outside': b'bad'}, '非法路径')

    def test_single_source_edition_is_rejected(self):
        metadata = self.metadata() | {'CFBundleDisplayName': '红果鉴'}
        self.check_rejected({'Payload/Runner.app/Info.plist': plistlib.dumps(metadata)}, '应用名称')

    def test_simulator_package_is_rejected(self):
        metadata = self.metadata() | {'CFBundleSupportedPlatforms': ['iPhoneSimulator']}
        self.check_rejected({'Payload/Runner.app/Info.plist': plistlib.dumps(metadata)}, '真机包')

    def test_missing_executable_is_rejected(self):
        self.check_rejected({'Payload/Runner.app/Info.plist': plistlib.dumps(self.metadata())}, '缺少 Runner')


if __name__ == '__main__':
    unittest.main()
