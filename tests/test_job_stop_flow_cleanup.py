"""Unit tests for SDN Switch Flow Reset and Counter Teardown on Lab Stop (TEST-02).

Verifies SDN-01:
1. _job_stop() invokes /dos/flows/clear FIRST with X-Internal-Token to purge OVS switch drop flows.
2. _job_stop() invokes /dos/reset SECOND with X-Internal-Token to reset runtime counters.
3. Call sequence and order are strictly preserved (flows/clear then reset).
4. Failures or timeouts when contacting Ryu controller are caught, logged, and do not crash lab teardown.
"""

import os
import sys
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch, MagicMock, call

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from labs.job_manager import _job_stop, LabState, _set_current_state


class TestJobStopFlowCleanup(unittest.TestCase):
    """Test suite verifying /dos/flows/clear and /dos/reset execution during _job_stop()."""

    def setUp(self):
        _set_current_state(LabState.LAB_READY, 'Test ready state')

    def tearDown(self):
        _set_current_state(LabState.IDLE, 'Teardown state')

    @patch('labs.job_manager.load_internal_token', return_value='tok_secret_sdn_999')
    @patch('labs.job_manager._stop_net')
    @patch('labs.job_manager._stop_attack')
    @patch('labs.job_manager._stop_active_pcap')
    @patch('urllib.request.urlopen')
    def test_job_stop_invokes_flows_clear_then_reset_with_token(
        self, mock_urlopen, mock_pcap, mock_attack, mock_net, mock_tok
    ):
        """Verify _job_stop calls /dos/flows/clear first, then /dos/reset, both carrying X-Internal-Token."""
        # Setup mock urlopen context manager return
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = _job_stop()
        self.assertTrue(res.get('ok'))
        self.assertFalse(res.get('running'))

        # Check urlopen was called exactly twice
        self.assertEqual(mock_urlopen.call_count, 2)

        # Inspect the requests
        req1 = mock_urlopen.call_args_list[0][0][0]
        req2 = mock_urlopen.call_args_list[1][0][0]

        self.assertIsInstance(req1, urllib.request.Request)
        self.assertIsInstance(req2, urllib.request.Request)

        # 1st request must be /dos/flows/clear
        self.assertTrue(req1.full_url.endswith('/dos/flows/clear'), f"1st call was {req1.full_url}, expected /dos/flows/clear")
        self.assertEqual(req1.get_method(), 'POST')
        self.assertEqual(req1.headers.get('X-internal-token'), 'tok_secret_sdn_999')
        self.assertEqual(req1.headers.get('Content-type'), 'application/json')

        # 2nd request must be /dos/reset
        self.assertTrue(req2.full_url.endswith('/dos/reset'), f"2nd call was {req2.full_url}, expected /dos/reset")
        self.assertEqual(req2.get_method(), 'POST')
        self.assertEqual(req2.headers.get('X-internal-token'), 'tok_secret_sdn_999')
        self.assertEqual(req2.headers.get('Content-type'), 'application/json')

    @patch('labs.job_manager.load_internal_token', return_value='tok_custom_111')
    @patch('labs.job_manager._stop_net')
    @patch('labs.job_manager._stop_attack')
    @patch('labs.job_manager._stop_active_pcap')
    @patch('urllib.request.urlopen')
    def test_job_stop_custom_port(self, mock_urlopen, mock_pcap, mock_attack, mock_net, mock_tok):
        """Verify RYU_REST_PORT environment variable is honored for flow clear and reset."""
        orig_port = os.environ.get('RYU_REST_PORT')
        try:
            os.environ['RYU_REST_PORT'] = '8099'
            mock_resp = MagicMock()
            mock_resp.__enter__.return_value = mock_resp
            mock_urlopen.return_value = mock_resp

            res = _job_stop()
            self.assertTrue(res.get('ok'))

            req1 = mock_urlopen.call_args_list[0][0][0]
            req2 = mock_urlopen.call_args_list[1][0][0]

            self.assertIn(':8099/dos/flows/clear', req1.full_url)
            self.assertIn(':8099/dos/reset', req2.full_url)
        finally:
            if orig_port is not None:
                os.environ['RYU_REST_PORT'] = orig_port
            else:
                os.environ.pop('RYU_REST_PORT', None)

    @patch('labs.job_manager.load_internal_token', return_value='tok_resilience_test')
    @patch('labs.job_manager._stop_net')
    @patch('labs.job_manager._stop_attack')
    @patch('labs.job_manager._stop_active_pcap')
    @patch('urllib.request.urlopen')
    def test_job_stop_handles_controller_error_resiliently(
        self, mock_urlopen, mock_pcap, mock_attack, mock_net, mock_tok
    ):
        """Verify errors contacting Ryu (e.g. connection refused) do not cause _job_stop to crash."""
        mock_urlopen.side_effect = urllib.error.URLError('Connection refused')

        with self.assertLogs('labs.job_manager', level='WARNING') as cm:
            res = _job_stop()

        self.assertTrue(res.get('ok'))
        self.assertFalse(res.get('running'))
        self.assertTrue(mock_net.called)

        # Confirm warnings were logged for both clear and reset failure
        log_text = '\n'.join(cm.output)
        self.assertIn('Failed to clear OVS switch flows on stop', log_text)
        self.assertIn('Failed to reset Ryu counters on stop', log_text)

    @patch('labs.job_manager.load_internal_token', return_value='')
    @patch('labs.job_manager._stop_net')
    @patch('labs.job_manager._stop_attack')
    @patch('labs.job_manager._stop_active_pcap')
    @patch('urllib.request.urlopen')
    def test_job_stop_without_token_handles_gracefully(
        self, mock_urlopen, mock_pcap, mock_attack, mock_net, mock_tok
    ):
        """Verify when internal token is empty, request proceeds without X-Internal-Token header."""
        mock_resp = MagicMock()
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        res = _job_stop()
        self.assertTrue(res.get('ok'))

        req1 = mock_urlopen.call_args_list[0][0][0]
        self.assertNotIn('X-internal-token', req1.headers)


if __name__ == '__main__':
    unittest.main()
