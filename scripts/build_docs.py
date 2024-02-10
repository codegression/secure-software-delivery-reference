"""Build deterministic report and fixture exhibit from executed test observations."""
import hashlib
import html
import json
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def build(report):
    fixture_path = ROOT / 'data/fictional_permits.json'
    fixture = json.loads(fixture_path.read_text())
    manifest = {'fixture': 'data/fictional_permits.json', 'sha256': hashlib.sha256(fixture_path.read_bytes()).hexdigest(),
                'users': len(fixture['users']), 'tenants': len({u['tenant'] for u in fixture['users']}),
                'permits': len(fixture['permits']), 'origin': 'Original fictional fixture; CC0-1.0'}
    (ROOT / 'docs/fixture-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    template = (ROOT / 'scripts/exhibit.html').read_text()
    page = template.replace('__PASSED__', str(report['passed'])).replace('__TOTAL__', str(report['tests_run']))
    page = page.replace('__FIXTURE__', json.dumps(fixture, ensure_ascii=True).replace('<', '\\u003c'))
    (ROOT / 'docs/index.html').write_text(page)
    lines = [
        '# Fieldbook: control evidence and release decision', '',
        '**Decision:** accept this repository as a local application-security demonstration. Do not treat it as a production deployment approval.', '',
        f"The executed suite passed **{report['passed']} of {report['tests_run']} real HTTP test scenarios**, with {report['failed']} failures, {report['errors']} errors and {report['skipped']} skipped tests. The evidence comes from isolated SQLite fixtures and actual loopback connections. It is not a percentage of all possible security controls or an estimate of vulnerability prevalence.", '',
        '## Findings that matter to a delivery lead', '',
        '| Question | Observed behavior | Decision implication |',
        '| --- | --- | --- |',
        '| Can one team inspect or decide another team’s proposal? | The tested read and mutation attempts return 404; stored proposal stays pending after denied mutation. | Tenant policy is enforced on server-side object lookup. |',
        '| Can the author approve their own proposal? | Reviewer self-approval returns 403 and leaves the state unchanged. | The independent-review invariant survives direct API calls. |',
        '| Can racing reviews overwrite each other? | Two concurrent requests produce one 200 and one 409, and only one decision audit event. | Guarded state transition plus transaction preserves the tested invariant. |',
        '| Is a copied old cookie still useful after sign-out, expiry or rotation? | Those requests return 401 in the corresponding isolated tests. | Sessions are revocable and have server-side expiry. |',
        '| Can a foreign web page submit a authenticated decision? | Missing/wrong CSRF or incorrect Origin is denied; foreign Host is rejected. | Browser-origin boundary has complementary controls. |',
        '| Does security work block legitimate researchers? | Authorized submission and independent review persist the expected owner, team, state, reviewer and audit event. | Positive workflow evidence accompanies negative tests. |', '',
        '## Release scope and priorities', '',
        '1. **Keep the lab local.** The server binds to 127.0.0.1, serves HTTP and intentionally omits Secure on its local cookie. It is not a production web server.',
        '2. **Replace local identity for real use.** Managed identity, MFA, recovery and account lifecycle need ownership and testing.',
        '3. **Close assurance gaps before deployment.** Add supported hosting/TLS, browser and accessibility tests, current dependency advisories, persistent abuse controls, external audit retention and backup restoration tests.', '',
        '## Exact executed scenarios', '', '| Test | Outcome |', '| --- | --- |'
    ]
    for row in report['observations']:
        lines.append(f"| `{row['test'].split('.')[-1]}` | {row['outcome']} |")
    lines += ['', '## Limits of this result', ''] + ['- ' + value for value in report['limitations']]
    lines += ['', 'Source archive packaging uses fixed timestamps and an allowlist; local passwords and databases are excluded. The CI workflow is provided, but no remote GitHub execution or branch-protection setting is claimed.', '',
              'Regenerate: `python3 run.py verify`. Machine-readable observations: [evaluation.json](evaluation.json). Method and threat boundaries: [threat-model.md](threat-model.md).', '']
    (ROOT / 'docs/control-report.md').write_text('\n'.join(lines))


if __name__ == '__main__':
    build(json.loads((ROOT / 'docs/evaluation.json').read_text()))
