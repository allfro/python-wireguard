import datetime
import unittest
from ipaddress import ip_network, ip_address
import socket

import wireguard as wg


class TestWireGuardMethods(unittest.TestCase):

    def setUp(self):
        self.device = wg.add_device('test0')

    def tearDown(self):
        if self.device:
            wg.del_device(self.device)
            self.device = None

    def test_add_device(self):
        self.assertIsInstance(self.device, wg.WireGuardDevice)
        self.assertIn('test0', wg.list_device_names())

    def test_list_device_names(self):
        self.assertListEqual(['test0'], wg.list_device_names())

    def test_del_device(self):
        self.assertIn('test0', wg.list_device_names())
        self.tearDown()
        self.assertNotIn('test0', wg.list_device_names())

    def test_get_invalid_device(self):
        self.assertRaises(OSError, lambda: wg.get_device('test1'))

    def test_generate_private_key(self):
        for i in range(1000):
            k = wg.generate_private_key()
            b = k.encode()
            self.assertIsInstance(k, wg.PrivateKey)
            self.assertEqual(32, len(b))
            self.assertNotEqual(b'\x00'*32, b)
            self.assertLessEqual(b[31], 127)
            self.assertGreaterEqual(b[31], 64)
            self.assertLessEqual(b[0], 248)
            if b[0]:
                self.assertGreaterEqual(b[0], 8)

    def test_generate_preshared_key(self):
        k = wg.generate_preshared_key()
        self.assertIsInstance(k, wg.PrivateKey)
        self.assertEqual(32, len(k.encode()))
        self.assertNotEqual(b'\x00'*32, k.encode())



class TestAllowedIPMethods(unittest.TestCase):

    def test_from_ip4_network(self):
        a = wg.AllowedIP.from_ip_network(ip_network('192.168.0.0/24'))
        self.assertEqual(a.address, ip_network('192.168.0.0/24'))
        self.assertEqual(a.cidr, 24)
        self.assertEqual(a.family, socket.AF_INET)

    def test_equal(self):
        w = wg.wg_allowedip_p(wg.wg_allowedip(family=socket.AF_INET))
        self.assertEqual(wg.AllowedIP(w).pointer, wg.AllowedIP(w).pointer)

    def test_from_ip6_network(self):
        a = wg.AllowedIP.from_ip_network(ip_network('fe08::/32'))
        self.assertEqual(a.address, ip_network('fe08::/32'))
        self.assertEqual(a.cidr, 32)
        self.assertEqual(a.family, socket.AF_INET6)

    def test_from_ip4_network_str(self):
        a = wg.AllowedIP.from_ip_network('192.168.0.0/24')
        self.assertEqual(a.address, ip_network('192.168.0.0/24'))
        self.assertEqual(a.cidr, 24)
        self.assertEqual(a.family, socket.AF_INET)

    def test_from_ip6_network_str(self):
        a = wg.AllowedIP.from_ip_network('fe08::/32')
        self.assertEqual(a.address, ip_network('fe08::/32'))
        self.assertEqual(a.cidr, 32)
        self.assertEqual(a.family, socket.AF_INET6)

    def test_change_cidr(self):
        a = wg.AllowedIP.from_ip_network('fe08::/32')
        self.assertEqual(a.address, ip_network('fe08::/32'))
        self.assertEqual(a.cidr, 32)
        self.assertEqual(a.family, socket.AF_INET6)
        a.cidr = 24
        self.assertEqual(a.cidr, 24)

    def test_allowed_ip_chain(self):
        a = wg.AllowedIP.from_ip_network('fe08::/32')
        n = wg.AllowedIP.from_ip_network('192.168.0.0/24')
        a.next_allowed_ip = n
        self.assertEqual(a.next_allowed_ip, n)
        self.assertEqual(a.address, ip_network('fe08::/32'))
        self.assertEqual(a.next_allowed_ip.address, ip_network('192.168.0.0/24'))

    def test_change_invalid_family(self):
        a = wg.AllowedIP.from_ip_network('192.168.0.0/24')
        a.family = 0
        self.assertIsNone(a.address)

    def test_change_address_str(self):
        a = wg.AllowedIP.from_ip_network('192.168.0.0/24')
        a.address = '192.168.2.0/24'
        self.assertEqual(ip_network('192.168.2.0/24'), a.address)

    def test_bool_for_null(self):
        self.assertFalse(wg.AllowedIP())

    def test_bool_for_non_null(self):
        self.assertTrue(wg.AllowedIP(wg.wg_allowedip_p(wg.wg_allowedip())))

    def test_repr(self):
        a = wg.AllowedIP.from_ip_network('192.168.0.0/24')
        self.assertEqual('<AllowedIP cidr="192.168.0.0/24">', repr(a))

    def test_str(self):
        a = wg.AllowedIP.from_ip_network('192.168.0.0/24')
        self.assertEqual('192.168.0.0/24', str(a))


class TestWireGuardEndpointMethods(unittest.TestCase):

    def test_from_address_and_port_ipv4_address(self):
        wge = wg.WireGuardEndpoint.from_address_and_port(ip_address('192.168.0.1'), 1337)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET, wge.family)
        self.assertEqual(ip_address('192.168.0.1'), wge.address)

    def test_from_address_and_port_ipv6_address(self):
        wge = wg.WireGuardEndpoint.from_address_and_port(ip_address('fe08::1'), 1337)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET6, wge.family)
        self.assertEqual(ip_address('fe08::1'), wge.address)

    def test_from_address_and_port_ipv4_address_str(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('192.168.0.1', 1337)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET, wge.family)
        self.assertEqual(ip_address('192.168.0.1'), wge.address)

    def test_from_address_and_port_ipv6_address_str(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET6, wge.family)
        self.assertEqual(ip_address('fe08::1'), wge.address)

    def test_change_port(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET6, wge.family)
        self.assertEqual(ip_address('fe08::1'), wge.address)
        wge.port = 1338
        self.assertEqual(1338, wge.port)

    def test_invalid_family_address(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge.family = 0
        self.assertIsNone(wge.address)
        self.assertIsNone(wge.port)

    def test_change_port_for_invalid_family_address(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge.family = 0

        def change_port():
            wge.port = 1

        self.assertRaises(ValueError, change_port)

    def test_change_scope_id_for_invalid_family_address(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge.family = socket.AF_INET

        def change_scope_id():
            wge.scope_id = 1

        self.assertRaises(ValueError, change_scope_id)

    def test_change_flow_info_for_invalid_family_address(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge.family = socket.AF_INET

        def change_flow_info():
            wge.flow_info = 1

        self.assertRaises(ValueError, change_flow_info)

    def test_change_address(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge.address = ip_address('192.168.0.1')
        self.assertEqual(ip_address('192.168.0.1'), wge.address)

    def test_change_address_str(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge.address = '192.168.0.1'
        self.assertEqual(ip_address('192.168.0.1'), wge.address)

    def test_flow_info(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge.flow_info = 12
        self.assertEqual(12, wge.flow_info)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET6, wge.family)
        self.assertEqual(ip_address('fe08::1'), wge.address)

    def test_scope_id(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge.scope_id = 12
        self.assertEqual(12, wge.scope_id)
        self.assertEqual(1337, wge.port)
        self.assertEqual(socket.AF_INET6, wge.family)
        self.assertEqual(ip_address('fe08::1'), wge.address)

    def test_repr(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        self.assertEqual('<WireGuardEndpoint endpoint="fe08::1:1337">', repr(wge))

    def test_str(self):
        wge = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        self.assertEqual('fe08::1:1337', str(wge))

    def test_equal(self):
        wge1 = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        wge2 = wg.WireGuardEndpoint.from_address_and_port('fe08::1', 1337)
        self.assertEqual(wge1, wge2)


class TestWireGuardPeerMethods(unittest.TestCase):

    def test_new_wireguard_peer(self):
        pub = wg.PrivateKey.generate().public_key
        psk = wg.PrivateKey.generate()
        wgp = wg.WireGuardPeer.from_config(
            pub,
            psk,
            wg.WireGuardEndpoint.from_address_and_port('192.168.0.1', 1337),
            [wg.AllowedIP.from_ip_network('192.168.0.0/24'), wg.AllowedIP.from_ip_network('192.168.1.0/24')],
            21
        )

        self.assertEqual(pub, wgp.public_key)
        self.assertEqual(psk, wgp.preshared_key)
        self.assertEqual(wg.WireGuardEndpoint.from_address_and_port('192.168.0.1', 1337), wgp.endpoint)
        self.assertListEqual(
            [wg.AllowedIP.from_ip_network('192.168.0.0/24'), wg.AllowedIP.from_ip_network('192.168.1.0/24')],
            list(wgp.allowed_ips)
        )
        self.assertEqual(21, wgp.persistent_keepalive_interval)
        self.assertEqual(wgp.first_allowed_ip, wg.AllowedIP.from_ip_network('192.168.0.0/24'))
        self.assertEqual(wgp.last_allowed_ip, wg.AllowedIP.from_ip_network('192.168.1.0/24'))
        self.assertFalse(wgp.next_peer)

    def test_new_wireguard_public_key_set(self):
        pub = wg.PrivateKey.generate().public_key

        wgp = wg.WireGuardPeer.from_config(
            wg.PrivateKey.generate().public_key
        )

        wgp.public_key = pub

        self.assertEqual(pub, wgp.public_key)
        self.assertEqual(wg.WGPeerFlags.WGPEER_HAS_PUBLIC_KEY, wgp.flags & wg.WGPeerFlags.WGPEER_HAS_PUBLIC_KEY)

    def test_new_wireguard_public_key_set_null(self):
        wgp = wg.WireGuardPeer.from_config(wg.PrivateKey.generate().public_key)
        wgp.public_key = None
        self.assertEqual(wg.PublicKey(b'\x00' * 32), wgp.public_key)

    def test_new_wireguard_preshared_key_set(self):
        psk = wg.PrivateKey.generate()

        wgp = wg.WireGuardPeer.from_config(
            wg.PrivateKey.generate().public_key
        )

        wgp.preshared_key = psk

        self.assertEqual(psk, wgp.preshared_key)
        self.assertEqual(wg.WGPeerFlags.WGPEER_HAS_PRESHARED_KEY, wgp.flags & wg.WGPeerFlags.WGPEER_HAS_PRESHARED_KEY)

    def test_new_wireguard_preshared_key_set_null(self):
        wgp = wg.WireGuardPeer.from_config(wg.PrivateKey.generate().public_key, wg.PrivateKey.generate())
        wgp.preshared_key = None
        self.assertEqual(wg.PrivateKey(b'\x00' * 32), wgp.preshared_key)

    def test_set_endpoint_null(self):
        wgp = wg.WireGuardPeer.from_config(
            wg.PrivateKey.generate().public_key,
            endpoint=wg.WireGuardEndpoint.from_address_and_port('192.168.0.1', 443)
        )

        wgp.endpoint = None

        self.assertEqual('None:None', str(wgp.endpoint))

    def test_get_last_handshake_time(self):
        wgp = wg.WireGuardPeer.from_config(None)
        self.assertEqual(datetime.datetime(1969, 12, 31, 19, 0), wgp.last_handshake_time)

    def test_get_rx_bytes(self):
        wgp = wg.WireGuardPeer.from_config(None)
        self.assertEqual(0, wgp.rx_bytes)

    def test_get_tx_bytes(self):
        wgp = wg.WireGuardPeer.from_config(None)
        self.assertEqual(0, wgp.tx_bytes)

    def test_get_persistent_keepalive_interval(self):
        wgp = wg.WireGuardPeer.from_config(None)
        self.assertEqual(0, wgp.persistent_keepalive_interval)

        wgp.persistent_keepalive_interval = 21
        self.assertEqual(21, wgp.persistent_keepalive_interval)
        self.assertEqual(
            wg.WGPeerFlags.WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL,
            wgp.flags & wg.WGPeerFlags.WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL
        )

    def test_get_persistent_keepalive_interval_set_null(self):
        wgp = wg.WireGuardPeer.from_config(None, persistent_keepalive_interval=21)
        self.assertEqual(21, wgp.persistent_keepalive_interval)

        wgp.persistent_keepalive_interval = 0
        self.assertEqual(0, wgp.persistent_keepalive_interval)
        self.assertEqual(
            0,
            wgp.flags & wg.WGPeerFlags.WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL
        )

    def test_add_allowed_ip_to_populated_list(self):
        wgp = wg.WireGuardPeer.from_config(
            None,
            allowed_ips=[wg.AllowedIP.from_ip_network('192.168.0.0/24'), wg.AllowedIP.from_ip_network('192.168.1.0/24')]
        )

        wgp.add_allowed_ip(wg.AllowedIP.from_ip_network('192.168.3.0/24'))

        self.assertListEqual(
            [
                wg.AllowedIP.from_ip_network('192.168.0.0/24'),
                wg.AllowedIP.from_ip_network('192.168.1.0/24'),
                wg.AllowedIP.from_ip_network('192.168.3.0/24')
            ],
            list(wgp.allowed_ips)
        )
        self.assertEqual(wgp.last_allowed_ip, wg.AllowedIP.from_ip_network('192.168.3.0/24'))

    def test_add_allowed_ip_to_empty_list(self):
        wgp = wg.WireGuardPeer.from_config(None)

        wgp.add_allowed_ip(wg.AllowedIP.from_ip_network('192.168.3.0/24'))

        self.assertListEqual(
            [wg.AllowedIP.from_ip_network('192.168.3.0/24')],
            list(wgp.allowed_ips)
        )
        self.assertEqual(wgp.first_allowed_ip, wg.AllowedIP.from_ip_network('192.168.3.0/24'))
        self.assertEqual(wgp.last_allowed_ip, wg.AllowedIP.from_ip_network('192.168.3.0/24'))

    def test_fetch_empty_allowed_ips(self):
        wgp = wg.WireGuardPeer.from_config(None)
        self.assertListEqual(
            [],
            list(wgp.allowed_ips)
        )

    def test_set_empty_allowed_ips(self):
        wgp = wg.WireGuardPeer.from_config(None, allowed_ips=[wg.AllowedIP.from_ip_network('192.168.3.0/24')])
        wgp.allowed_ips = []
        self.assertListEqual(
            [],
            list(wgp.allowed_ips)
        )

    def test_remove_peer(self):
        wgp = wg.WireGuardPeer.from_config(None)
        wgp.remove()
        self.assertEqual(
            wg.WGPeerFlags.WGPEER_REMOVE_ME,
            wgp.flags & wg.WGPeerFlags.WGPEER_REMOVE_ME
        )

    def test_equal(self):
        wgp = wg.WireGuardPeer.from_config(None)
        self.assertEqual(wgp, wgp)


class TestWireGuardDeviceMethods(unittest.TestCase):

    def setUp(self):
        self.device = wg.add_device("test0")

    def tearDown(self):
        wg.del_device(self.device)
        self.device = None

    def applyChanges(self):
        self.device.save()
        self.device = wg.get_device(self.device)

    def assertFlagSet(self, flag):
        self.assertEqual(
            flag,
            self.device.flags & flag
        )

    def test_get_name(self):
        self.assertEqual('test0', self.device.name)

    def test_set_private_key(self):
        priv = wg.PrivateKey.generate()
        self.device.private_key = priv
        self.applyChanges()
        self.assertEqual(priv, self.device.private_key)
        self.assertEqual(priv.public_key, self.device.public_key)
        self.assertFlagSet(wg.WGDeviceFlags.WGDEVICE_HAS_PRIVATE_KEY | wg.WGDeviceFlags.WGDEVICE_HAS_PUBLIC_KEY)

    def test_get_ifindex(self):
        self.assertTrue(self.device.ifindex)

    def test_set_private_key_null(self):
        self.device.private_key = wg.PrivateKey.generate()
        self.applyChanges()
        self.device.private_key = None
        self.applyChanges()
        self.assertEqual(wg.PrivateKey(b'\x00'*32), self.device.private_key)
        self.assertEqual(wg.PublicKey(b'\x00'*32), self.device.public_key)

    def test_get_fwmark(self):
        self.assertFalse(self.device.fwmark)

    def test_set_fwmark(self):
        self.device.fwmark = 32
        self.applyChanges()
        self.assertEqual(32, self.device.fwmark)
        self.device.fwmark = 0
        self.applyChanges()
        self.assertEqual(0, self.device.fwmark)

    def test_get_listen_port(self):
        self.assertFalse(self.device.listen_port)

    def test_set_listen_port(self):
        self.device.listen_port = 32
        self.applyChanges()
        self.assertEqual(32, self.device.listen_port)
        self.device.listen_port = 0
        self.applyChanges()
        self.assertEqual(0, self.device.listen_port)

    def test_add_peer(self):
        pub1 = wg.PublicKey(wg.random(32))
        self.device.add_peer(wg.WireGuardPeer.from_config(pub1))
        self.applyChanges()
        self.assertEqual(pub1, list(self.device.peers)[0].public_key)

        pub2 = wg.PublicKey(wg.random(32))
        self.device.add_peer(wg.WireGuardPeer.from_config(pub2))
        self.applyChanges()
        self.assertEqual(pub2, list(self.device.peers)[1].public_key)

    def test_set_peers(self):
        pub1 = wg.PublicKey(wg.random(32))
        pub2 = wg.PublicKey(wg.random(32))
        self.device.peers = [wg.WireGuardPeer.from_config(pub1), wg.WireGuardPeer.from_config(pub2)]
        self.applyChanges()
        self.assertEqual([pub1, pub2], list(p.public_key for p in self.device.peers))

    def test_set_empty_peers(self):
        pub1 = wg.PublicKey(wg.random(32))
        pub2 = wg.PublicKey(wg.random(32))
        self.device.peers = [wg.WireGuardPeer.from_config(pub1)]
        self.applyChanges()
        self.assertEqual([pub1], list(p.public_key for p in self.device.peers))
        self.device.peers = [wg.WireGuardPeer.from_config(pub1), wg.WireGuardPeer.from_config(pub2)]
        self.applyChanges()
        self.assertEqual([pub1, pub2], list(p.public_key for p in self.device.peers))
        self.device.peers = []
        self.applyChanges()
        self.assertFalse(list(self.device.peers))

    def test_sub_structure_integrity(self):
        pub = wg.PublicKey(wg.random(32))
        psk = wg.PrivateKey.generate()
        self.device.add_peer(
            wg.WireGuardPeer.from_config(
                pub,
                psk,
        ('192.168.0.1', 443),
                [
                    '192.168.0.0/24', '192.168.1.0/24'
                ],
                21
            )
        )

        self.applyChanges()
        peer = next(self.device.peers)
        self.assertEqual(pub, peer.public_key)
        self.assertEqual(psk, peer.preshared_key)
        self.assertEqual('192.168.0.1:443', str(peer.endpoint))
        self.assertListEqual(
            [wg.AllowedIP.from_ip_network('192.168.0.0/24'), wg.AllowedIP.from_ip_network('192.168.1.0/24')],
            list(peer.allowed_ips)
        )


if __name__ == '__main__':
    unittest.main()
