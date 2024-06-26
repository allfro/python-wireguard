import unittest
from ipaddress import ip_network, ip_address
import socket

from wireguard import __init__ as wg


class TestWireGuardMethods(unittest.TestCase):

    def test_add_device(self):
        w = wg.add_device('wg0')
        self.assertIsInstance(w, wg.WireGuardDevice)
        self.assertIn('wg0', wg.list_device_names())
        wg.del_device('wg0')

    def test_list_device_names(self):
        self.assertTrue(isinstance(wg.list_device_names(), list))

    def test_del_device(self):
        wg.add_device('wg0')
        self.assertIn('wg0', wg.list_device_names())
        wg.del_device('wg0')
        self.assertNotIn('wg0', wg.list_device_names())


class TestAllowedIPMethods(unittest.TestCase):

    def test_new_allowed_ip_from_ip4_network(self):
        a = wg.AllowedIP.from_ip_network(ip_network('192.168.0.0/24'))
        self.assertEqual(a.address, ip_network('192.168.0.0/24'))
        self.assertEqual(a.cidr, 24)
        self.assertEqual(a.family, socket.AF_INET)

    def test_pointers_equal(self):
        w = wg.wg_allowedip_p(wg.wg_allowedip(family=socket.AF_INET))
        self.assertEqual(wg.AllowedIP(w).pointer, wg.AllowedIP(w).pointer)

    def test_new_allowed_ip_from_ip6_network(self):
        a = wg.AllowedIP.from_ip_network(ip_network('fe08::/32'))
        self.assertEqual(a.address, ip_network('fe08::/32'))
        self.assertEqual(a.cidr, 32)
        self.assertEqual(a.family, socket.AF_INET6)

    def test_new_allowed_ip_from_ip4_network_str(self):
        a = wg.AllowedIP.from_ip_network('192.168.0.0/24')
        self.assertEqual(a.address, ip_network('192.168.0.0/24'))
        self.assertEqual(a.cidr, 24)
        self.assertEqual(a.family, socket.AF_INET)

    def test_new_allowed_ip_from_ip6_network_str(self):
        a = wg.AllowedIP.from_ip_network('fe08::/32')
        self.assertEqual(a.address, ip_network('fe08::/32'))
        self.assertEqual(a.cidr, 32)
        self.assertEqual(a.family, socket.AF_INET6)

    def test_new_allowed_ip_change_cidr(self):
        a = wg.AllowedIP.from_ip_network('fe08::/32')
        self.assertEqual(a.address, ip_network('fe08::/32'))
        self.assertEqual(a.cidr, 32)
        self.assertEqual(a.family, socket.AF_INET6)
        a.cidr = 24
        self.assertEqual(a.cidr, 24)

    def test_new_allowed_ip_chain(self):
        a = wg.AllowedIP.from_ip_network('fe08::/32')
        n = wg.AllowedIP.from_ip_network('192.168.0.0/24')
        a.next_allowed_ip = n
        self.assertEqual(a.next_allowed_ip, n)
        self.assertEqual(a.address, ip_network('fe08::/32'))
        self.assertEqual(a.next_allowed_ip.address, ip_network('192.168.0.0/24'))


class TestWireGuardPeer(unittest.TestCase):

    def test_new_wireguard_endpoint_from_ipv4_address(self):
        wge = wg.WireGuardEndpoint.from_address_and_port(ip_address('192.168.0.1'), 1337)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET, wge.family)
        self.assertEqual(ip_address('192.168.0.1'), wge.address)

    def test_new_wireguard_endpoint_from_ipv6_address(self):
        wge = wg.WireGuardEndpoint.from_address_and_port(ip_address('fe08::1'), 1337)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET6, wge.family)
        self.assertEqual(ip_address('fe08::1'), wge.address)

    def test_new_wireguard_endpoint_from_ipv4_address_str(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('192.168.0.1', 1337)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET, wge.family)
        self.assertEqual(ip_address('192.168.0.1'), wge.address)

    def test_new_wireguard_endpoint_from_ipv6_address_str(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET6, wge.family)
        self.assertEqual(ip_address('fe08::1'), wge.address)

    def test_new_wireguard_endpoint_change_port(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET6, wge.family)
        self.assertEqual(ip_address('fe08::1'), wge.address)
        wge.port = 1338
        self.assertEqual(1338, wge.port)

    def test_new_wireguard_endpoint_flowinfo(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge.flow_info = 12
        self.assertEqual(12, wge.flow_info)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET6, wge.family)
        self.assertEqual(ip_address('fe08::1'), wge.address)

    def test_new_wireguard_endpoint_flowinfo(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge.scope_id = 12
        self.assertEqual(12, wge.scope_id)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET6, wge.family)
        self.assertEqual(ip_address('fe08::1'), wge.address)


if __name__ == '__main__':
    unittest.main()
