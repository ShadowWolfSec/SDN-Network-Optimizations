"""
tests/test_attack_scenario_custom_attackers.py
=============================================
Unit tests verifying custom attacker selection and threshold enforcement for DDoS presets.
"""

import unittest
from unittest import mock

from labs.attack_engine import AttackValidationError, run_attack_preset


class DummyHost:
    def __init__(self, name, ip='10.0.0.1', linked=True):
        self.name = name
        self._ip = ip
        self.intfs = {'eth0': True} if linked else {}

    def IP(self):
        return self._ip

    def popen(self, *args, **kwargs):
        p = mock.MagicMock()
        p.poll.return_value = None
        return p


class DummyNet:
    def __init__(self, hosts):
        self.hosts = hosts

    def get(self, name):
        for h in self.hosts:
            if h.name == name:
                return h
        raise KeyError(name)


class TestCustomAttackerSelection(unittest.TestCase):
    def setUp(self):
        # Topology with 8 hosts: h1..h8
        self.hosts = [DummyHost(f'h{i}', f'10.0.0.{i}') for i in range(1, 9)]
        self.net = DummyNet(self.hosts)

    @mock.patch('shutil.which', return_value='/usr/bin/hping3')
    def test_ddos_medium_custom_attackers_applied(self, mock_which):
        """When attackers_override is provided, those exact attackers are selected with no mixed legit pings."""
        chosen = ['h1', 'h3', 'h4', 'h5']
        res = run_attack_preset(
            self.net,
            kind='ddos',
            profile='medium',
            duration=5,
            mixed=True,
            capture=False,
            proto='syn',
            min_ddos_sources=4,
            preferred_victim='h2',
            attackers_override=chosen,
        )
        self.assertTrue(res.get('ok'))
        atk = res.get('attack') or {}
        self.assertEqual(atk.get('attackers'), chosen)
        self.assertEqual(atk.get('legitimate'), [])  # No background legit pings to confuse user

    @mock.patch('shutil.which', return_value='/usr/bin/hping3')
    def test_ddos_insufficient_custom_attackers_rejected(self, mock_which):
        """Selecting fewer attackers than min_ddos_sources raises AttackValidationError."""
        chosen = ['h1', 'h3']  # Only 2, but min is 4
        with self.assertRaises(AttackValidationError) as ctx:
            run_attack_preset(
                self.net,
                kind='ddos',
                profile='medium',
                duration=5,
                mixed=True,
                capture=False,
                proto='syn',
                min_ddos_sources=4,
                preferred_victim='h2',
                attackers_override=chosen,
            )
        self.assertEqual(ctx.exception.error, 'insufficient_attackers')

    @mock.patch('shutil.which', return_value='/usr/bin/hping3')
    def test_ddos_blocked_attacker_rejected(self, mock_which):
        """Selecting a currently blocked attacker raises AttackValidationError."""
        chosen = ['h1', 'h3', 'h4', 'h5']
        blocked = {'10.0.0.3'}  # h3 is blocked
        with self.assertRaises(AttackValidationError) as ctx:
            run_attack_preset(
                self.net,
                kind='ddos',
                profile='medium',
                duration=5,
                mixed=True,
                capture=False,
                proto='syn',
                min_ddos_sources=4,
                blocked_ips=blocked,
                preferred_victim='h2',
                attackers_override=chosen,
            )
        self.assertEqual(ctx.exception.error, 'attacker_blocked')

    @mock.patch('shutil.which', return_value='/usr/bin/hping3')
    def test_ddos_fallback_auto_select_when_omitted(self, mock_which):
        """When attackers_override is omitted, fallback auto-selection is preserved for legacy tests."""
        res = run_attack_preset(
            self.net,
            kind='ddos',
            profile='medium',
            duration=5,
            mixed=True,
            capture=False,
            proto='syn',
            min_ddos_sources=4,
            preferred_victim='h2',
            attackers_override=None,
        )
        self.assertTrue(res.get('ok'))
        atk = res.get('attack') or {}
        self.assertEqual(len(atk.get('attackers', [])), 3)  # ATTACK_MAX_ATTACKERS_MEDIUM defaults to 3 in env/test
        self.assertTrue(len(atk.get('legitimate', [])) > 0)


if __name__ == '__main__':
    unittest.main()
