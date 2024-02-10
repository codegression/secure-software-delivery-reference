"""Record observed HTTP control checks, not broad security coverage percentages."""
import json
import sys
import unittest
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class EvidenceResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.observations = []

    def addSuccess(self, test):
        super().addSuccess(test)
        self.observations.append({'test': test.id(), 'outcome': 'pass'})

    def addFailure(self, test, error):
        super().addFailure(test, error)
        self.observations.append({'test': test.id(), 'outcome': 'fail'})

    def addError(self, test, error):
        super().addError(test, error)
        self.observations.append({'test': test.id(), 'outcome': 'error'})


def evaluate():
    suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'))
    result = unittest.TextTestRunner(stream=sys.stderr, verbosity=1, resultclass=EvidenceResult).run(suite)
    report = {
        'method': 'Real loopback HTTP requests against a fresh SQLite fixture per test; concurrent review uses two independent HTTP connections.',
        'dataset': 'data/fictional_permits.json', 'tests_run': result.testsRun,
        'passed': result.testsRun - len(result.failures) - len(result.errors) - len(result.skipped),
        'failed': len(result.failures), 'errors': len(result.errors), 'skipped': len(result.skipped),
        'observations': sorted(result.observations, key=lambda x: x['test']),
        'limitations': [
            'Passing scenarios are evidence for the stated assertions, not a vulnerability prevalence or universal security-coverage estimate.',
            'The XSS check verifies JSON content type, CSP and rendering sink convention; browser exploit execution is outside this suite.',
            'No TLS, public deployment, live CVE feed, independent penetration test, accessibility audit or sustained load test was performed.',
            'Rate limiting and concurrent review cover bounded lab cases only; process-local rate state resets on restart.'
        ]
    }
    (ROOT / 'docs' / 'evaluation.json').write_text(json.dumps(report, indent=2) + '\n')
    if not result.wasSuccessful():
        raise SystemExit(1)
    return report


if __name__ == '__main__':
    evaluate()
