"""Make a repeatable allowlisted source artifact. Never package var/ or credentials."""
import hashlib
import sys
import zipfile
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from scripts.policy_check import check, release_files


def package():
    check()
    directory = ROOT / 'dist'
    directory.mkdir(exist_ok=True)
    destination = directory / 'mosslight-fieldbook-source.zip'
    with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in release_files():
            name = path.relative_to(ROOT).as_posix()
            member = zipfile.ZipInfo('mosslight-fieldbook/' + name, (2026, 1, 1, 0, 0, 0))
            member.external_attr = 0o100644 << 16
            member.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(member, path.read_bytes())
    digest = hashlib.sha256(destination.read_bytes()).hexdigest()
    (directory / 'SHA256SUMS').write_text(digest + '  ' + destination.name + '\n')
    return destination


if __name__ == '__main__':
    print(package())
