"""Exercise the actual socket server, including failures and persisted side effects."""
import http.client
import json
import shutil
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
from mosslight.security import ITERATIONS, hash_password, token_hash, verify_password
from mosslight.server import FieldbookServer
from mosslight.store import connect, initialize


class APIControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.seed_dir = tempfile.TemporaryDirectory()
        cls.base = Path(cls.seed_dir.name) / 'base.sqlite'
        cls.credentials = initialize(cls.base)

    @classmethod
    def tearDownClass(cls):
        cls.seed_dir.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.database = Path(self.temp.name) / 'test.sqlite'
        shutil.copy(self.base, self.database)
        self.server = FieldbookServer(self.database, port=0)
        self.worker = threading.Thread(target=self.server.serve_forever, kwargs={'poll_interval': .01}, daemon=True)
        self.worker.start()
        self.addCleanup(self.cleanup_server)

    def cleanup_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.worker.join(timeout=2)
        self.temp.cleanup()

    def request(self, path, method='GET', data=None, session=None, headers=None, raw=None):
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=8)
        merged = {'Origin': self.server.origin, 'Content-Type': 'application/json'} if method == 'POST' else {}
        if session:
            merged.update({'Cookie': session['cookie'], 'X-CSRF-Token': session['csrf']})
        if headers:
            merged.update(headers)
        merged = {key: value for key, value in merged.items() if value is not None}
        body = raw if raw is not None else json.dumps(data).encode() if data is not None else None
        try:
            connection.request(method, path, body, merged)
            response = connection.getresponse()
            payload = response.read()
            response_headers = dict(response.getheaders())
            if response_headers.get('Content-Type', '').startswith('application/json'):
                payload = json.loads(payload)
            return response.status, payload, response_headers
        finally:
            connection.close()

    def login(self, name='alba', previous=None):
        status, body, headers = self.request('/api/login', 'POST', {'username': name, 'password': self.credentials[name]}, session=previous)
        self.assertEqual(status, 200, body)
        return {'cookie': headers['Set-Cookie'].split(';')[0], 'csrf': body['csrf']}

    def test_authentication_requires_valid_credentials(self):
        self.assertEqual(self.request('/api/permits')[0], 401)
        for name in ['alba', 'not-a-user']:
            code, body, _ = self.request('/api/login', 'POST', {'username': name, 'password': 'incorrect-password'})
            self.assertEqual((code, body), (401, {'error': 'Invalid credentials'}))

    def test_password_hashes_use_random_salts_and_work_factor(self):
        with closing(connect(self.database)) as db:
            encoded = db.execute('SELECT password_hash FROM users WHERE username=?', ('alba',)).fetchone()[0]
        self.assertEqual(encoded.split('$')[1], str(ITERATIONS))
        self.assertTrue(verify_password(self.credentials['alba'], encoded))
        self.assertNotIn(self.credentials['alba'], encoded)
        self.assertNotEqual(hash_password('same input'), hash_password('same input'))

    def test_session_cookie_and_browser_response_policy(self):
        code, _, headers = self.request('/api/login', 'POST', {'username': 'alba', 'password': self.credentials['alba']})
        self.assertEqual(code, 200)
        for attribute in ['HttpOnly', 'SameSite=Strict', 'Max-Age=1800', 'Path=/']:
            self.assertIn(attribute, headers['Set-Cookie'])
        self.assertNotIn('Secure', headers['Set-Cookie'])  # Explicit local HTTP exception.
        code, _, headers = self.request('/')
        self.assertEqual(code, 200)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertIn("script-src 'self'", headers['Content-Security-Policy'])
        self.assertNotIn('unsafe-inline', headers['Content-Security-Policy'])
        self.assertEqual(headers['X-Content-Type-Options'], 'nosniff')
        self.assertNotIn('Access-Control-Allow-Origin', headers)

    def test_session_secret_hashed_in_database(self):
        session = self.login()
        token = session['cookie'].split('=', 1)[1]
        with closing(connect(self.database)) as db:
            stored = db.execute('SELECT token_hash FROM sessions').fetchone()[0]
        self.assertEqual(stored, token_hash(token))
        self.assertNotEqual(stored, token)
        self.assertNotIn(token.encode(), self.database.read_bytes())

    def test_relogin_rotates_and_invalidates_previous_cookie(self):
        old = self.login()
        new = self.login(previous=old)
        self.assertNotEqual(new['cookie'], old['cookie'])
        self.assertNotEqual(new['csrf'], old['csrf'])
        self.assertEqual(self.request('/api/session', session=old)[0], 401)
        self.assertEqual(self.request('/api/session', session=new)[0], 200)

    def test_expired_session_denied(self):
        session = self.login()
        with closing(connect(self.database)) as db, db:
            db.execute('UPDATE sessions SET expires=?', (int(time.time()) - 1,))
        self.assertEqual(self.request('/api/permits', session=session)[0], 401)

    def test_logout_revokes_session(self):
        session = self.login()
        self.assertEqual(self.request('/api/logout', 'POST', {}, session)[0], 200)
        self.assertEqual(self.request('/api/session', session=session)[0], 401)

    def test_submitter_only_sees_own_objects(self):
        session = self.login()
        code, body, _ = self.request('/api/permits', session=session)
        self.assertEqual(code, 200)
        self.assertEqual({p['id'] for p in body['permits']}, {101, 103})
        self.assertEqual(self.request('/api/permits/102', session=session)[0], 404)
        self.assertEqual(self.request('/api/permits/101', session=session)[0], 200)

    def test_reviewer_can_see_same_tenant_only(self):
        session = self.login('mira')
        code, body, _ = self.request('/api/permits', session=session)
        self.assertEqual(code, 200)
        self.assertEqual(len(body['permits']), 6)
        self.assertTrue(all(p['tenant'] == 'fern-coast' for p in body['permits']))
        self.assertEqual(self.request('/api/permits/201', session=session)[0], 404)

    def test_cross_tenant_mutation_denied(self):
        session = self.login('nico')
        code, _, _ = self.request('/api/permits/101/review', 'POST', {'decision': 'approved', 'note': 'This must never be applied.'}, session)
        self.assertEqual(code, 404)
        with closing(connect(self.database)) as db:
            self.assertEqual(db.execute('SELECT status FROM permits WHERE id=101').fetchone()[0], 'pending')

    def test_submitter_cannot_review(self):
        session = self.login()
        self.assertEqual(self.request('/api/permits/101/review', 'POST', {'decision': 'approved', 'note': 'This must never be applied.'}, session)[0], 403)

    def test_reviewer_cannot_approve_own_proposal(self):
        session = self.login('mira')
        self.assertEqual(self.request('/api/permits/106/review', 'POST', {'decision': 'approved', 'note': 'Trying to bypass a second reviewer.'}, session)[0], 403)
        with closing(connect(self.database)) as db:
            self.assertEqual(db.execute('SELECT status FROM permits WHERE id=106').fetchone()[0], 'pending')

    def test_review_writes_decision_and_audit_atomically(self):
        session = self.login('mira')
        self.assertEqual(self.request('/api/permits/101/review', 'POST', {'decision': 'approved', 'note': 'Use the established paths only.'}, session)[0], 200)
        code, body, _ = self.request('/api/permits/101', session=session)
        self.assertEqual((code, body['permit']['status'], body['permit']['reviewed_by'], body['permit']['version']), (200, 'approved', 3, 2))
        code, body, _ = self.request('/api/audit', session=session)
        self.assertTrue(any(e['action'] == 'permit_reviewed' and e['object_id'] == 101 and e['detail'] == 'approved' for e in body['events']))

    def test_duplicate_and_concurrent_review_have_one_winner(self):
        session = self.login('mira')
        def review(decision):
            return self.request('/api/permits/101/review', 'POST', {'decision': decision, 'note': 'Independent concurrent review request.'}, session)[0]
        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(review, ['approved', 'rejected']))
        self.assertEqual(sorted(results), [200, 409])
        with closing(connect(self.database)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM audit WHERE action='permit_reviewed'").fetchone()[0], 1)

    def test_missing_and_wrong_csrf_rejected_without_change(self):
        session = self.login()
        for header in [None, 'incorrect']:
            self.assertEqual(self.request('/api/logout', 'POST', {}, session, {'X-CSRF-Token': header})[0], 403)
        self.assertEqual(self.request('/api/session', session=session)[0], 200)

    def test_login_requires_exact_origin(self):
        for origin in [None, 'https://outside.invalid', self.server.origin + '.outside.invalid']:
            self.assertEqual(self.request('/api/login', 'POST', {'username': 'alba', 'password': self.credentials['alba']}, headers={'Origin': origin})[0], 403)

    def test_authenticated_writes_reject_cross_origin_and_fetch_site(self):
        session = self.login()
        self.assertEqual(self.request('/api/logout', 'POST', {}, session, {'Origin': 'https://outside.invalid'})[0], 403)
        self.assertEqual(self.request('/api/logout', 'POST', {}, session, {'Sec-Fetch-Site': 'cross-site'})[0], 403)

    def test_host_rebinding_rejected(self):
        self.assertEqual(self.request('/', headers={'Host': 'outside.invalid'})[0], 400)
        self.assertEqual(self.request('/', headers={'Host': 'localhost:' + str(self.server.server_port)})[0], 400)

    def test_login_rate_limit_reached(self):
        for _ in range(6):
            self.assertEqual(self.request('/api/login', 'POST', {'username': 'alba', 'password': 'wrong'})[0], 401)
        code, _, headers = self.request('/api/login', 'POST', {'username': 'alba', 'password': 'wrong'})
        self.assertEqual(code, 429)
        self.assertEqual(headers['Retry-After'], '60')

    def test_mass_assignment_rejected_and_tenant_set_server_side(self):
        session = self.login()
        proposal = {'species': 'Synthetic fern', 'location': 'Fictional plot', 'purpose': 'Observe growth using photographs only.'}
        self.assertEqual(self.request('/api/permits', 'POST', {**proposal, 'tenant': 'high-marsh', 'owner_id': 4, 'status': 'approved'}, session)[0], 400)
        code, body, _ = self.request('/api/permits', 'POST', proposal, session)
        self.assertEqual(code, 201)
        code, result, _ = self.request('/api/permits/' + str(body['id']), session=session)
        self.assertEqual((result['permit']['tenant'], result['permit']['owner_id'], result['permit']['status']), ('fern-coast', 1, 'pending'))

    def test_sql_injection_login_does_not_authenticate(self):
        code, _, _ = self.request('/api/login', 'POST', {'username': "' OR 1=1 --", 'password': 'anything'})
        self.assertEqual(code, 401)

    def test_script_payload_is_data_and_not_reflected_as_html(self):
        session = self.login()
        payload = '<img src=x onerror=alert(1)>'
        code, result, _ = self.request('/api/permits', 'POST', {'species': payload, 'location': 'Synthetic plot', 'purpose': 'An inert string to exercise output rendering.'}, session)
        self.assertEqual(code, 201)
        code, result, headers = self.request('/api/permits/' + str(result['id']), session=session)
        self.assertEqual(result['permit']['species'], payload)
        self.assertEqual(headers['Content-Type'], 'application/json; charset=utf-8')
        js = self.request('/app.js')[1].decode()
        self.assertNotIn('.innerHTML', js)
        self.assertNotIn('insertAdjacentHTML', js)
        self.assertIn('.textContent', js)

    def test_invalid_json_duplicate_fields_and_body_limits(self):
        for raw in [b'{', b'[]', b'{"username":"alba","username":"nico","password":"x"}', b'{"username":NaN,"password":"x"}']:
            self.assertEqual(self.request('/api/login', 'POST', raw=raw)[0], 400)
        self.assertEqual(self.request('/api/login', 'POST', raw=b'x' * 16_385)[0], 413)
        self.assertEqual(self.request('/api/login', 'POST', {}, headers={'Content-Type': 'text/plain'})[0], 415)

    def test_audit_scoped_and_forbidden_to_submitter(self):
        alba = self.login()
        self.assertEqual(self.request('/api/audit', session=alba)[0], 403)
        mira = self.login('mira')
        self.login('nico')
        code, body, _ = self.request('/api/audit', session=mira)
        self.assertEqual(code, 200)
        self.assertEqual({event['tenant'] for event in body['events']}, {'fern-coast'})
        self.assertNotIn('password', json.dumps(body))
        self.assertNotIn(alba['csrf'], json.dumps(body))

    def test_static_route_whitelist_blocks_database_and_traversal(self):
        session = self.login()
        for path in ['/var/fieldbook.sqlite', '/../data/fictional_permits.json', '/static/../../README.md']:
            self.assertEqual(self.request(path, session=session)[0], 404)
        self.assertEqual(self.request('/api/permits', 'DELETE', session=session)[0], 405)


if __name__ == '__main__':
    unittest.main()
