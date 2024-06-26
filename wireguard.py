import os
import socket
import struct
from ctypes import *
from ctypes.util import find_library
from datetime import datetime
from ipaddress import ip_network, IPv4Network, IPv6Network, ip_address, IPv4Address, IPv6Address
from typing import List

from nacl.public import PrivateKey, PublicKey
from nacl.utils import random

libwg = CDLL('./libwg.so')

libc = CDLL(find_library('c'))

errno_location = libc.__errno_location
errno_location.restype = POINTER(c_int)


def errcheck(ret, func, args):
    if ret:
        e = errno_location()[0]
        raise OSError(os.strerror(e))
    return ret


IFNAMSIZ = 16

wg_peer_flags = c_int
wg_device_flags = c_int


class in_addr(Structure):
    _fields_ = [
        ("s_addr", c_uint32)
    ]


# Define the sockaddr structure
class sockaddr(Structure):
    _fields_ = [
        ("sa_family", c_ushort),
        ("sa_data", c_ubyte * 14)
    ]


# Define the sockaddr_in structure (IPv4)
class sockaddr_in(Structure):
    _fields_ = [
        ("sin_family", c_ushort),
        ("sin_port", c_ushort),
        ("sin_addr", in_addr),  # in_addr represented as a 32-bit integer
        ("sin_zero", c_ubyte * 8)  # Padding to match the size of sockaddr
    ]


# Define the in6_addr structure
class in6_addr(Structure):
    _fields_ = [
        ("s6_addr", c_ubyte * 16)
    ]


# Define the sockaddr_in6 structure (IPv6)
class sockaddr_in6(Structure):
    _fields_ = [
        ("sin6_family", c_ushort),
        ("sin6_port", c_ushort),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", in6_addr),
        ("sin6_scope_id", c_uint32)
    ]


class WGDeviceFlags:
    WGDEVICE_REPLACE_PEERS = wg_device_flags(1 << 0),
    WGDEVICE_HAS_PRIVATE_KEY = wg_device_flags(1 << 1),
    WGDEVICE_HAS_PUBLIC_KEY = wg_device_flags(1 << 2),
    WGDEVICE_HAS_LISTEN_PORT = wg_device_flags(1 << 3),
    WGDEVICE_HAS_FWMARK = wg_device_flags(1 << 4)


class WGPeerFlags:
    WGPEER_REMOVE_ME = wg_peer_flags(1 << 0),
    WGPEER_REPLACE_ALLOWEDIPS = wg_peer_flags(1 << 1),
    WGPEER_HAS_PUBLIC_KEY = wg_peer_flags(1 << 2)
    WGPEER_HAS_PRESHARED_KEY = wg_peer_flags(1 << 3)
    WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = wg_peer_flags(1 << 4)


wg_key = c_ubyte * 32
wg_key_p = POINTER(wg_key)


class timespec64(Structure):
    _fields_ = [
        ("tv_sec", c_int64),
        ("tv_nsec", c_int64)
    ]


class wg_endpoint(Union):
    _fields_ = [
        ("addr", sockaddr),
        ("addr4", sockaddr_in),
        ("addr6", sockaddr_in6)
    ]


wg_endpoint_p = POINTER(wg_endpoint)


class addr(Union):
    _fields_ = [
        ("ip4", in_addr),
        ("ip6", in6_addr)
    ]


class wg_allowedip(Structure):
    pass


wg_allowedip_p = POINTER(wg_allowedip)

wg_allowedip._anonymous_ = ("addr",)
wg_allowedip._fields_ = [
    ("family", c_uint16),
    ("addr", addr),
    ("cidr", c_uint8),
    ("next_allowedip", wg_allowedip_p)
]


class wg_peer(Structure):
    pass


wg_peer_p = POINTER(wg_peer)

wg_peer._fields_ = [
    ("flags", wg_peer_flags),
    ("public_key", wg_key),
    ("preshared_key", wg_key),
    ("endpoint", wg_endpoint),
    ("last_handshake_time", timespec64),
    ("rx_bytes", c_uint64),
    ("tx_bytes", c_uint64),
    ("persistent_keepalive_interval", c_uint16),
    ("first_allowedip", wg_allowedip_p),
    ("last_allowedip", wg_allowedip_p),
    ("next_peer", wg_peer_p),
]

wg_peer_p = POINTER(wg_peer)


class wg_device(Structure):
    _fields_ = [
        ("name", c_char * IFNAMSIZ),
        ("ifindex", c_uint32),
        ("wg_device_flags", wg_device_flags),
        ("public_key", wg_key),
        ("private_key", wg_key),
        ("fwmark", c_uint32),
        ("listen_port", c_uint16),
        ("first_peer", wg_peer_p),
        ("last_peer", wg_peer_p)
    ]


wg_device_p = POINTER(wg_device)

wg_get_device = libwg.wg_get_device
wg_get_device.argtypes = (POINTER(wg_device_p), c_char_p)
wg_get_device.restype = c_int
wg_get_device.errcheck = errcheck

wg_set_device = libwg.wg_set_device
wg_set_device.argtypes = (wg_device_p,)
wg_set_device.restype = c_int
wg_set_device.errcheck = errcheck

wg_add_device = libwg.wg_add_device
wg_add_device.argtypes = (c_char_p,)
wg_add_device.restype = c_int
wg_add_device.errcheck = errcheck

wg_del_device = libwg.wg_del_device
wg_del_device.argtypes = (c_char_p,)
wg_del_device.restype = c_int
wg_del_device.errcheck = errcheck

wg_free_device = libwg.wg_free_device
wg_free_device.argtypes = (wg_device_p,)
wg_free_device.restype = None

wg_list_device_names = libwg.wg_list_device_names
wg_list_device_names.restype = POINTER(c_ubyte)


class AllowedIP:

    def __init__(self, allowed_ip_pointer: wg_allowedip_p):
        self._allowed_ip_pointer = allowed_ip_pointer or wg_allowedip_p(wg_allowedip())
        self.allowed_ip = allowed_ip_pointer.contents

    @staticmethod
    def from_ip_network(net: Union[IPv4Network, IPv6Network, str]):
        if isinstance(net, str):
            net = ip_network(net, strict=False)
        aip = AllowedIP(wg_allowedip_p(wg_allowedip()))
        aip.address = net
        return aip

    @property
    def family(self):
        return self.allowed_ip.family

    @family.setter
    def family(self, value):
        self.allowed_ip.family = value

    @property
    def address(self) -> Union[IPv6Network, IPv4Network]:
        family = self.family
        address = None
        if family == socket.AF_INET:
            address = socket.inet_ntop(socket.AF_INET, struct.pack(self.allowed_ip.addr.ip4.s_addr))
        elif family == socket.AF_INET6:
            address = socket.inet_ntop(socket.AF_INET6, bytes(self.allowed_ip.addr.ip6.s6_addr))
        else:
            raise ValueError(f'Invalid socket family: {family}')
        return ip_network(f'{address}/{self.allowed_ip.cidr}')

    @address.setter
    def address(self, value: Union[IPv6Network, IPv4Network, str]):
        if isinstance(value, str):
            value = ip_network(value, strict=False)

        is_ipv4 = isinstance(value, IPv4Network)
        self.family = socket.AF_INET if is_ipv4 else socket.AF_INET6
        self.allowed_ip.cidr = value.prefixlen
        if is_ipv4:
            self.allowed_ip.addr.ip4.s_addr = int(value.network_address)
        else:
            memmove(self.allowed_ip.addr.ip6.s6_addr, value.network_address.packed, sizeof(in6_addr))

    @property
    def cidr(self):
        return self.allowed_ip.cidr

    @cidr.setter
    def cidr(self, value):
        self.allowed_ip.cidr = value

    @property
    def next_allowed_ip(self):
        return AllowedIP(self.allowed_ip.next_allowedip)

    @next_allowed_ip.setter
    def next_allowed_ip(self, value):
        self.allowed_ip.next_allowedip = value.pointer

    @property
    def pointer(self):
        return self._allowed_ip_pointer

    def __eq__(self, other):
        return isinstance(self, AllowedIP) and self.pointer == other.pointer


class WireGuardEndpoint:

    def __init__(self, endpoint: wg_endpoint = None):
        self.endpoint = endpoint or wg_endpoint()

    @staticmethod
    def from_address_and_port(address: Union[IPv4Address, IPv6Address, str], port: int):
        if isinstance(address, str):
            address = ip_address(address)

        wge = WireGuardEndpoint()
        wge.address = address
        wge.port = port
        return wge

    @property
    def family(self):
        return self.endpoint.addr.sa_family

    @family.setter
    def family(self, value):
        self.endpoint.addr.sa_family = value

    @property
    def address(self):
        family = self.family
        if family == socket.AF_INET:
            return socket.inet_ntop(socket.AF_INET, struct.pack(self.endpoint.addr4.sin_addr.s_addr))
        elif family == socket.AF_INET6:
            return socket.inet_ntop(socket.AF_INET6, bytes(self.endpoint.addr6.sin6_addr.s6_addr))
        raise ValueError(f'Invalid socket family: {family}')

    @address.setter
    def address(self, value: Union[IPv6Address, IPv4Address, str]):
        if isinstance(value, str):
            value = ip_address(value)

        is_ipv4 = isinstance(value, IPv4Network)
        self.family = socket.AF_INET if is_ipv4 else socket.AF_INET6

        if is_ipv4:
            self.endpoint.addr4.sin_addr.s_addr = int(value)
        else:
            memmove(self.endpoint.addr6.sin6_addr.s6_addr, value.packed, sizeof(in6_addr))

    @property
    def port(self):
        family = self.family
        if family == socket.AF_INET:
            return socket.htons(self.endpoint.addr4.sin_port)
        elif family == socket.AF_INET6:
            return socket.htons(self.endpoint.addr6.sin6_port)
        raise ValueError(f'Invalid socket family: {family}')

    @port.setter
    def port(self, value):
        family = self.family
        if family == socket.AF_INET:
            self.endpoint.addr4.sin_port = value
        elif family == socket.AF_INET6:
            self.endpoint.addr6.sin6_port = value
        else:
            raise ValueError(f'Invalid socket family: {family}')

    @property
    def flowinfo(self):
        family = self.family
        if family == socket.AF_INET6:
            return self.endpoint.addr6.sin6_flowinfo
        return None

    @flowinfo.setter
    def flowinfo(self, value):
        family = self.family
        if family == socket.AF_INET6:
            self.endpoint.addr6.sin6_flowinfo = value
        else:
            raise ValueError(f'Invalid socket family: {family}')

    def __repr__(self):
        return f'<{self.__class__.__name__} family={self.family} address={self.address} port={self.port}>'


class WireGuardPeer:
    def __init__(self, peer_pointer: wg_peer_p):
        self._peer_pointer = peer_pointer or wg_peer_p(wg_peer(
            flags=WGPeerFlags.WGPEER_HAS_PUBLIC_KEY | WGPeerFlags.WGPEER_REPLACE_ALLOWEDIPS
        ))
        self.peer = peer_pointer.contents

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(bytes(self.peer.public_key))

    @public_key.setter
    def public_key(self, value):
        memmove(self.peer.public_key, value.encode(), 32)

    @property
    def preshared_key(self) -> PrivateKey:
        return PrivateKey(bytes(self.peer.preshared_key))

    @preshared_key.setter
    def preshared_key(self, value):
        memmove(self.peer.preshared_key, value.encode(), 32)

    @property
    def endpoint(self):
        return WireGuardEndpoint(self.peer.endpoint)

    @property
    def last_handshake_time(self):
        t = self.peer.last_handshake_time
        total_seconds = t.tv_sec + (t.tv_usec / 1000000.0)
        return datetime.fromtimestamp(total_seconds)

    @property
    def rx_bytes(self):
        return self.peer.rx_bytes

    @property
    def tx_bytes(self):
        return self.peer.tx_bytes

    @property
    def persistent_keepalive_interval(self):
        return self.peer.persistent_keepalive_interval

    @persistent_keepalive_interval.setter
    def persistent_keepalive_interval(self, value):
        self.peer.persistent_keepalive_interval = value

    @property
    def first_allowed_ip(self) -> AllowedIP:
        return AllowedIP(self.peer.first_allowedip)

    @first_allowed_ip.setter
    def first_allowed_ip(self, value: AllowedIP):
        self.peer.first_allowedip = value.pointer

    @property
    def last_allowed_ip(self) -> AllowedIP:
        return AllowedIP(self.peer.last_allowedip)

    @last_allowed_ip.setter
    def last_allowed_ip(self, value: AllowedIP):
        self.peer.last_allowedip = value.pointer

    @property
    def pointer(self):
        return self._peer_pointer

    @property
    def next_peer(self):
        return WireGuardPeer(self.peer.next_peer)

    @next_peer.setter
    def next_peer(self, value):
        self.peer.next_peer = value.pointer

    @property
    def allowed_ips(self) -> List[AllowedIP]:
        allowed_ips = []
        if not self.first_allowed_ip:
            return allowed_ips

        allowed_ips.append(self.first_allowed_ip)
        current = self.first_allowed_ip

        while current != self.last_allowed_ip:
            current = current.next_peer
            allowed_ips.append(current)

        return allowed_ips

    def __eq__(self, other):
        return isinstance(other, WireGuardPeer) and self.pointer == other.pointer


class WireGuardDevice:

    def __init__(self, device_pointer: wg_device_p):
        self._device_pointer = device_pointer
        self.device: wg_device = device_pointer.contents

    def __bytes__(self):
        return self.device.name

    @property
    def ifindex(self) -> int:
        return self.device.ifindex

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(bytes(self.device.public_key))

    @public_key.setter
    def public_key(self, value):
        memmove(self.device.public_key, value.encode(), 32)

    @property
    def private_key(self) -> PrivateKey:
        if not self.device.private_key:
            raise ValueError('Private key is null')
        return PrivateKey(bytes(self.device.private_key))

    @private_key.setter
    def private_key(self, value: PrivateKey):
        memmove(self.device.private_key, value.encode(), 32)
        memmove(self.device.public_key, value.public_key.encode(), 32)

    @property
    def flags(self) -> int:
        return self.device.flags

    @flags.setter
    def flags(self, value):
        self.device.flags = value

    @property
    def fwmark(self) -> int:
        return self.device.fwmark

    @fwmark.setter
    def fwmark(self, value):
        self.device.fwmark = value

    @property
    def listen_port(self) -> int:
        return self.device.listen_port

    @listen_port.setter
    def listen_port(self, value):
        self.device.listen_port = value

    @property
    def first_peer(self) -> WireGuardPeer:
        return WireGuardPeer(self.device.first_peer)

    @first_peer.setter
    def first_peer(self, value: WireGuardPeer):
        self.device.first_peer = value.pointer

    @property
    def last_peer(self) -> WireGuardPeer:
        return WireGuardPeer(self.device.last_peer)

    @last_peer.setter
    def last_peer(self, value: WireGuardPeer):
        self.device.last_peer = value.pointer

    def __del__(self):
        wg_free_device(self._device_pointer)

    def add_peer(self, peer: WireGuardPeer):
        if not self.last_peer and not self.first_peer:
            self.last_peer = peer
            self.first_peer = peer
        else:
            self.last_peer.next_peer = peer
            self.last_peer = peer

    def remove_peer(self, peer: WireGuardPeer):
        peer.flags = WGPeerFlags.WGPEER_REMOVE_ME

    @property
    def peers(self):
        peers = []
        if not self.first_peer:
            return peers

        peers.append(self.first_peer)
        current = self.first_peer

        while current != self.last_peer:
            current = current.next_peer
            peers.append(current)

        return peers


def list_device_names():
    buf = wg_list_device_names()
    b = []
    i = 0
    l = -1

    while True:
        c = buf[i]
        if not c and not l:
            break
        b.append(c)
        l = c
        i += 1

    return [d.decode('utf8') for d in bytes(b).rstrip(b'\x00').split(b'\x00')]


def del_device(device_name: Union[WireGuardDevice, str]):
    wg_del_device(bytes(device_name, 'utf8'))


def add_device(device_name):
    wg_add_device(bytes(device_name, 'utf8'))
    return get_device(device_name)


def get_device(device_name):
    dev = wg_device_p()
    wg_get_device(pointer(dev), bytes(device_name, 'utf8'))
    return WireGuardDevice(dev)


def generate_key():
    secret = bytearray(random(PrivateKey.SIZE))
    secret[0] &= 248
    secret[31] = (secret[31] & 127) | 64
    return PrivateKey(secret)
