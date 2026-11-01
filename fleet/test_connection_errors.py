from unittest.mock import Mock, patch
import requests
from django.test import TestCase
from .models import Firewall
from .opnsense import OPNsenseClient, DeviceError


@patch.dict('os.environ', {'TEST_API_KEY':'test-key', 'TEST_API_SECRET':'test-secret'})
class ConnectionErrorTests(TestCase):
    def setUp(self):
        self.firewall = Firewall.objects.create(name='Test',base_url='https://fw.example.test',credential_prefix='TEST')

    @patch('fleet.opnsense.requests.Session')
    def test_transport_failures_are_distinct_and_do_not_expose_exception_details(self, session):
        for error, expected in [(requests.exceptions.SSLError, 'TLS handshake'),
                                (requests.exceptions.ProxyError, 'proxy connection'),
                                (requests.exceptions.ConnectTimeout, 'connection timed out'),
                                (requests.exceptions.ReadTimeout, 'within 30 seconds'),
                                (requests.exceptions.ConnectionError, 'connection failed'),
                                (OSError, 'CA bundle')]:
            with self.subTest(error=error):
                session.return_value.get.side_effect=error('private-credential-from-exception')
                with self.assertRaises(DeviceError) as caught:
                    OPNsenseClient(self.firewall).get('/api/firewall/filter/get')
                self.assertIn(expected,str(caught.exception))
                self.assertIn('/api/firewall/filter/get',str(caught.exception))
                self.assertNotIn('private-credential',str(caught.exception))

    @patch('fleet.opnsense.requests.Session')
    def test_http_status_has_actionable_endpoint_specific_error(self, session):
        for status, expected in [(401,'API key and secret'), (403,'privileges'), (404,'Endpoint not found'), (302,'redirected')]:
            with self.subTest(status=status):
                session.return_value.get.return_value=Mock(status_code=status)
                with self.assertRaisesMessage(DeviceError,expected):
                    OPNsenseClient(self.firewall).get('/api/firewall/group/get')

    @patch('fleet.opnsense.requests.Session')
    def test_html_login_page_is_reported_without_exposing_response_body(self, session):
        session.return_value.get.return_value=Mock(status_code=200)
        session.return_value.get.return_value.json.side_effect=ValueError('private-response-body')
        with self.assertRaisesMessage(DeviceError,'not valid JSON') as caught:
            OPNsenseClient(self.firewall).get('/api/firewall/filter/get')
        self.assertNotIn('private-response-body',str(caught.exception))
        self.assertIs(session.return_value.verify,True)
        self.assertFalse(session.return_value.get.call_args.kwargs['allow_redirects'])
