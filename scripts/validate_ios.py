import json
import plistlib
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path


def tool(*arguments):
    return subprocess.check_output(arguments, text=True).strip()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate_ipa(package, variant, report):
    with zipfile.ZipFile(package) as archive:
        require(archive.testzip() is None, 'IPA ZIP 校验失败')
        names = archive.namelist()
        prefix = 'Payload/Runner.app/'
        require(prefix + 'Info.plist' in names, 'IPA 缺少 Payload/Runner.app/Info.plist')
        require(all(not name.startswith('/') and '..' not in Path(name).parts for name in names),
                'IPA 包含非法路径')
        info = plistlib.loads(archive.read(prefix + 'Info.plist'))
        require(info['CFBundleDisplayName'] == variant.name, '应用名称与站源版本不一致')
        require(info['CFBundleName'] == variant.slug, '应用版本标识不一致')
        require(info['CFBundleIdentifier'] == 'com.duanju.duanjuApp', '应用标识异常')
        require(info.get('CFBundlePackageType') == 'APPL', '不是 iOS 应用')
        require(info.get('CFBundleSupportedPlatforms') == ['iPhoneOS'], '不是真机包')
        require(info.get('MinimumOSVersion') == '15.1', '最低系统版本异常')
        for relative in ['Runner', 'Frameworks/Flutter.framework/Flutter',
                         'Frameworks/App.framework/App', 'Frameworks/App.framework/flutter_assets/AssetManifest.bin']:
            require(prefix + relative in names, 'IPA 缺少 ' + relative)
        with tempfile.TemporaryDirectory() as directory:
            archive.extractall(directory)
            application = Path(directory) / 'Payload' / 'Runner.app'
            executable = application / info['CFBundleExecutable']
            symbols = tool('xcrun', 'nm', '-gU', str(executable))
            for symbol in ['_DuanjuRequest', '_DuanjuFree']:
                require(re.search(r'\b' + symbol + r'$', symbols, re.MULTILINE), 'FFI 入口缺失：' + symbol)
            binaries = []
            for path in sorted(application.rglob('*')):
                if not path.is_file():
                    continue
                with path.open('rb') as stream:
                    magic = stream.read(4)
                if magic not in [b'\xcf\xfa\xed\xfe', b'\xce\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xca\xfe\xba\xbf']:
                    continue
                architectures = tool('xcrun', 'lipo', '-archs', str(path)).split()
                require(architectures == ['arm64'], '非纯 ARM64 二进制：' + str(path))
                loads = tool('xcrun', 'otool', '-l', str(path))
                require('platform 2' in loads or 'LC_VERSION_MIN_IPHONEOS' in loads,
                        '二进制不是 iOS 真机目标：' + str(path))
                dependencies = []
                for line in tool('xcrun', 'otool', '-L', str(path)).splitlines()[1:]:
                    dependency = line.strip().split(' (')[0]
                    dependencies.append(dependency)
                    if dependency.startswith('@rpath/'):
                        require((application / 'Frameworks' / dependency.removeprefix('@rpath/')).is_file(),
                                '原生依赖未嵌入：' + dependency)
                    elif dependency.startswith('@loader_path/'):
                        require((path.parent / dependency.removeprefix('@loader_path/')).is_file(),
                                '原生依赖未嵌入：' + dependency)
                    elif dependency.startswith('@executable_path/'):
                        require((application / dependency.removeprefix('@executable_path/')).is_file(),
                                '原生依赖未嵌入：' + dependency)
                    else:
                        require(dependency.startswith(('/System/Library/', '/usr/lib/')),
                                '原生依赖使用构建机路径：' + dependency)
                binaries.append({'path': str(path.relative_to(application)),
                                 'architectures': architectures, 'dependencies': dependencies})
            require(any('mpv' in item['path'].lower() for item in binaries), '缺少 libmpv 播放库')
            require(any('ffmpegkit' in item['path'].lower() for item in binaries), '缺少 FFmpegKit 媒体库')
    result = {'package': package.name, 'edition': variant.slug, 'all_sources': variant.all_sources,
              'bundle_identifier': info['CFBundleIdentifier'], 'display_name': info['CFBundleDisplayName'],
              'minimum_os': info['MinimumOSVersion'], 'version': info['CFBundleShortVersionString'],
              'build': info['CFBundleVersion'], 'binaries': binaries,
              'validation': 'static only; signing, launch, search and playback require iPhone verification'}
    report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, ensure_ascii=False))
    return result
