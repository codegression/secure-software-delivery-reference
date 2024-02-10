"""Narrow release guardrails, not a general secret scanner or vulnerability assessment."""
import ast
import re
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
SCOPES = ['mosslight', 'static', 'scripts', 'tests', 'data', 'docs', '.github']
ROOT_FILES = ['run.py', 'README.md', 'LICENSE', 'Makefile', '.gitignore', 'SECURITY.md']


def release_files():
    files = [ROOT / name for name in ROOT_FILES]
    for scope in SCOPES:
        files.extend(p for p in (ROOT / scope).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc')
    return sorted(files, key=lambda p: p.relative_to(ROOT).as_posix())


def check():
    errors = []
    markers = [r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', r'gh[pousr]_[A-Za-z0-9]{36,}', r'AKIA[A-Z0-9]{16}']
    files = release_files()
    for path in files:
        if not path.exists():
            errors.append(f'Missing release file {path.name}')
            continue
        if path.suffix in {'.sqlite', '.db', '.key', '.pem'} or path.name.startswith('.env'):
            errors.append(f'Forbidden release file {path.name}')
        text = path.read_text(encoding='utf-8')
        if any(re.search(marker, text) for marker in markers):
            errors.append(f'Credential-shaped material: {path.relative_to(ROOT)}')
        if path.suffix == '.py':
            tree = ast.parse(text, filename=str(path))
            for item in ast.walk(tree):
                if isinstance(item, ast.Call) and isinstance(item.func, ast.Name) and item.func.id in {'eval', 'exec'}:
                    errors.append(f'Dynamic code execution: {path.name}:{item.lineno}')
                if isinstance(item, ast.keyword) and item.arg == 'shell' and isinstance(item.value, ast.Constant) and item.value.value is True:
                    errors.append(f'Shell execution: {path.name}:{item.lineno}')
    workflow = (ROOT / '.github/workflows/verify.yml').read_text()
    for action in re.findall(r'uses:\s*([^\s#]+)', workflow):
        if not re.fullmatch(r'[^@]+@[a-f0-9]{40}', action):
            errors.append(f'Action is not pinned: {action}')
    if 'pull_request_target' in workflow or 'contents: write' in workflow:
        errors.append('Unexpected privileged CI context')
    if 'persist-credentials: false' not in workflow:
        errors.append('Checkout must not persist credentials')
    if errors:
        raise SystemExit('\n'.join(errors))
    print(f'Policy gate: {len(files)} files checked; no configured pattern/policy violations.')
    return {'files_checked': len(files), 'violations': 0}


if __name__ == '__main__':
    check()
