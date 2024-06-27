import os
import socket
import struct
from ctypes import *
from ctypes.util import find_library
from datetime import datetime
from ipaddress import ip_network, IPv4Network, IPv6Network, ip_address, IPv4Address, IPv6Address
from typing import List, Generator, Tuple

from nacl.encoding import Base64Encoder
from nacl.public import PrivateKey, PublicKey
from nacl.utils import random

__all__ = [
    'Base64Encoder',
    'PrivateKey',
    'PublicKey',
    'generate_private_key',
    'generate_preshared_key',
    'add_device',
    'get_device',
    'del_device',
    'list_device_names',
    'ip_network',
    'ip_address',
    'WireGuardPeer',
    'WireGuardDevice',
    'WireGuardEndpoint',
    'AllowedIP',
    'WGDeviceFlags',
    'WGPeerFlags'
]

try:
    libwg = CDLL('./libwg.so')
except OSError:
    libwg = CDLL('./libwg/libwg.so')

libc = CDLL(find_library('c'))

errno_location = libc.__errno_location
errno_location.restype = POINTER(c_int)

calloc = libc.calloc
calloc.argtypes = (c_size_t, c_size_t)
calloc.restype = c_void_p


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
        ("sa_family", c_uint16),
        ("sa_data", c_ubyte * 14)
    ]


# Define the sockaddr_in structure (IPv4)
class sockaddr_in(Structure):
    _fields_ = [
        ("sin_family", c_uint16),
        ("sin_port", c_uint16),
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
        ("sin6_family", c_uint16),
        ("sin6_port", c_uint16),
        ("sin6_flowinfo", c_uint32),
        ("sin6_addr", in6_addr),
        ("sin6_scope_id", c_uint32)
    ]


class WGDeviceFlags:
    WGDEVICE_REPLACE_PEERS = 1 << 0
    WGDEVICE_HAS_PRIVATE_KEY = 1 << 1
    WGDEVICE_HAS_PUBLIC_KEY = 1 << 2
    WGDEVICE_HAS_LISTEN_PORT = 1 << 3
    WGDEVICE_HAS_FWMARK = 1 << 4


class WGPeerFlags:
    WGPEER_REMOVE_ME = 1 << 0
    WGPEER_REPLACE_ALLOWEDIPS = 1 << 1
    WGPEER_HAS_PUBLIC_KEY = 1 << 2
    WGPEER_HAS_PRESHARED_KEY = 1 << 3
    WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL = 1 << 4


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
        ("flags", wg_device_flags),
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

    def __init__(self, ptr: wg_allowedip_p = None):
        self._pointer = ptr or wg_allowedip_p()

    @staticmethod
    def from_ip_network(net: IPv4Network | IPv6Network | str):
        if isinstance(net, str):
            net = ip_network(net, strict=False)
        aip = AllowedIP(cast(calloc(1, sizeof(wg_allowedip)), wg_allowedip_p))
        aip.address = net
        return aip

    @property
    def family(self) -> int | None:
        return self._pointer.contents.family

    @family.setter
    def family(self, value) -> None:
        self._pointer.contents.family = value

    @property
    def address(self) -> IPv6Network | IPv4Network | None:
        family = self.family
        if family == socket.AF_INET:
            address = socket.inet_ntop(socket.AF_INET, struct.pack('I', self._pointer.contents.addr.ip4.s_addr))
        elif family == socket.AF_INET6:
            address = socket.inet_ntop(socket.AF_INET6, bytes(self._pointer.contents.addr.ip6.s6_addr))
        else:
            return None

        return ip_network(f'{address}/{self._pointer.contents.cidr}', strict=False)

    @address.setter
    def address(self, value: IPv6Network | IPv4Network | str) -> None:
        if isinstance(value, str):
            value = ip_network(value, strict=False)

        is_ipv4 = isinstance(value, IPv4Network)
        self.family = socket.AF_INET if is_ipv4 else socket.AF_INET6
        self._pointer.contents.cidr = value.prefixlen
        if is_ipv4:
            self._pointer.contents.ip4.s_addr = socket.htonl(int(value.network_address))
        else:
            memmove(self._pointer.contents.ip6.s6_addr, value.network_address.packed, sizeof(in6_addr))

    @property
    def cidr(self) -> int:
        return self._pointer.contents.cidr

    @cidr.setter
    def cidr(self, value: int) -> None:
        self._pointer.contents.cidr = value

    @property
    def next_allowed_ip(self):
        return AllowedIP(self._pointer.contents.next_allowedip)

    @next_allowed_ip.setter
    def next_allowed_ip(self, value) -> None:
        self._pointer.contents.next_allowedip = value.pointer if value else wg_allowedip_p()

    @property
    def pointer(self) -> wg_allowedip_p:
        return self._pointer

    def __eq__(self, other):
        return isinstance(other, AllowedIP) and self.address == other.address

    def __repr__(self):
        return f'<{self.__class__.__name__} cidr="{self.address}">'

    def __str__(self):
        return f'{self.address}'

    def __bool__(self):
        return bool(self._pointer)


class WireGuardEndpoint:

    def __init__(self, endpoint: wg_endpoint = None):
        self.endpoint = endpoint or wg_endpoint()

    @staticmethod
    def from_address_and_port(address: IPv4Address | IPv6Address | str, port: int):
        if isinstance(address, str):
            address = ip_address(address)

        wge = WireGuardEndpoint()
        wge.address = address
        wge.port = port
        return wge

    @property
    def family(self) -> int:
        return self.endpoint.addr.sa_family

    @family.setter
    def family(self, value) -> None:
        self.endpoint.addr.sa_family = value

    @property
    def address(self) -> IPv4Address | IPv6Address | None:
        family = self.family
        if family == socket.AF_INET:
            return ip_address(socket.inet_ntop(socket.AF_INET, struct.pack('I', self.endpoint.addr4.sin_addr.s_addr)))
        elif family == socket.AF_INET6:
            return ip_address(socket.inet_ntop(socket.AF_INET6, bytes(self.endpoint.addr6.sin6_addr.s6_addr)))

    @address.setter
    def address(self, value: IPv6Address | IPv4Address | str) -> None:
        if isinstance(value, str):
            value = ip_address(value)

        is_ipv4 = isinstance(value, IPv4Address)
        self.family = int(socket.AF_INET if is_ipv4 else socket.AF_INET6)

        if is_ipv4:
            self.endpoint.addr4.sin_addr.s_addr = socket.htonl(int(value))
        else:
            memmove(self.endpoint.addr6.sin6_addr.s6_addr, value.packed, sizeof(in6_addr))

    @property
    def port(self) -> int | None:
        family = self.family
        if family == socket.AF_INET:
            return socket.ntohs(self.endpoint.addr4.sin_port)
        elif family == socket.AF_INET6:
            return socket.ntohs(self.endpoint.addr6.sin6_port)

    @port.setter
    def port(self, value) -> None:
        family = self.family
        if family == socket.AF_INET:
            self.endpoint.addr4.sin_port = socket.htons(value)
        elif family == socket.AF_INET6:
            self.endpoint.addr6.sin6_port = socket.htons(value)
        else:
            raise ValueError(f'Unsupported socket family: {family}')

    @property
    def flow_info(self) -> int:
        family = self.family
        if family == socket.AF_INET6:
            return self.endpoint.addr6.sin6_flowinfo

    @flow_info.setter
    def flow_info(self, value) -> None:
        family = self.family
        if family == socket.AF_INET6:
            self.endpoint.addr6.sin6_flowinfo = value
        else:
            raise ValueError(f'Unsupported socket family: {family}')

    @property
    def scope_id(self) -> int:
        family = self.family
        if family == socket.AF_INET6:
            return self.endpoint.addr6.sin6_scope_id

    @scope_id.setter
    def scope_id(self, value) -> None:
        family = self.family
        if family == socket.AF_INET6:
            self.endpoint.addr6.sin6_scope_id = value
        else:
            raise ValueError(f'Unsupported socket family: {family}')

    def __repr__(self):
        return f'<{self.__class__.__name__} endpoint="{self}">'

    def __eq__(self, other):
        return isinstance(other, WireGuardEndpoint) and self.address == other.address and self.port == other.port

    def __str__(self):
        return f'{self.address}:{self.port}'


class WireGuardPeer:
    def __init__(self, ptr: wg_peer_p = None):
        self._pointer = ptr or wg_peer_p()

    @property
    def flags(self) -> PublicKey:
        return self._pointer.contents.flags

    @flags.setter
    def flags(self, value):
        self._pointer.contents.flags = value

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(bytes(self._pointer.contents.public_key))

    @public_key.setter
    def public_key(self, value):
        if not value:
            memset(self._pointer.contents.public_key, 0, sizeof(self._pointer.contents.public_key))
        else:
            self.flags |= WGPeerFlags.WGPEER_HAS_PUBLIC_KEY
            memmove(self._pointer.contents.public_key, value.encode(), 32)

    @property
    def preshared_key(self) -> PrivateKey:
        return PrivateKey(bytes(self._pointer.contents.preshared_key))

    @preshared_key.setter
    def preshared_key(self, value: PrivateKey):
        if not value:
            memset(self._pointer.contents.preshared_key, 0, sizeof(self._pointer.contents.preshared_key))
        else:
            self.flags |= WGPeerFlags.WGPEER_HAS_PRESHARED_KEY
            memmove(self._pointer.contents.preshared_key, value.encode(), sizeof(self._pointer.contents.preshared_key))

    @property
    def endpoint(self):
        return WireGuardEndpoint(self._pointer.contents.endpoint)

    @endpoint.setter
    def endpoint(self, value: WireGuardEndpoint | Tuple[str, int]):
        if not value:
            memset(byref(self._pointer.contents.endpoint), 0, sizeof(wg_endpoint))
        else:
            value = value if isinstance(value, WireGuardEndpoint) else WireGuardEndpoint.from_address_and_port(*value)
            memmove(byref(self._pointer.contents.endpoint), byref(value.endpoint), sizeof(wg_endpoint))

    @property
    def last_handshake_time(self):
        t = self._pointer.contents.last_handshake_time
        total_seconds = t.tv_sec + (t.tv_nsec / 1e9)
        return datetime.fromtimestamp(total_seconds)

    @property
    def rx_bytes(self):
        return self._pointer.contents.rx_bytes

    @property
    def tx_bytes(self):
        return self._pointer.contents.tx_bytes

    @property
    def persistent_keepalive_interval(self):
        return self._pointer.contents.persistent_keepalive_interval

    @persistent_keepalive_interval.setter
    def persistent_keepalive_interval(self, value):
        if value:
            self.flags |= WGPeerFlags.WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL
            self._pointer.contents.persistent_keepalive_interval = value
        else:
            self.flags ^= WGPeerFlags.WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL
            self._pointer.contents.persistent_keepalive_interval = 0

    @property
    def first_allowed_ip(self) -> AllowedIP:
        return AllowedIP(self._pointer.contents.first_allowedip)

    @first_allowed_ip.setter
    def first_allowed_ip(self, value: AllowedIP):
        self._pointer.contents.first_allowedip = value.pointer if value else wg_allowedip_p()

    @property
    def last_allowed_ip(self) -> AllowedIP:
        return AllowedIP(self._pointer.contents.last_allowedip)

    @last_allowed_ip.setter
    def last_allowed_ip(self, value: AllowedIP):
        self._pointer.contents.last_allowedip = value.pointer if value else wg_allowedip_p()

    def add_allowed_ip(self, value: AllowedIP):
        self.flags |= WGPeerFlags.WGPEER_REPLACE_ALLOWEDIPS

        if not self.first_allowed_ip:
            self.first_allowed_ip = value
            self.last_allowed_ip = value
        else:
            self.last_allowed_ip.next_allowed_ip = value
            self.last_allowed_ip = value
            self.last_allowed_ip.next_allowed_ip = None

    @property
    def pointer(self):
        return self._pointer

    @property
    def next_peer(self):
        return WireGuardPeer(self._pointer.contents.next_peer)

    @next_peer.setter
    def next_peer(self, value):
        self._pointer.contents.next_peer = value.pointer if value else wg_peer_p()

    @property
    def allowed_ips(self) -> Generator[AllowedIP, None, None]:
        if not self.first_allowed_ip:
            yield from ()
            return

        current = self.first_allowed_ip
        yield current

        while current != self.last_allowed_ip:
            current = current.next_allowed_ip
            if not current:
                break
            yield current

    def remove(self):
        self.flags = WGPeerFlags.WGPEER_REMOVE_ME

    @allowed_ips.setter
    def allowed_ips(self, value):
        self.flags |= WGPeerFlags.WGPEER_REPLACE_ALLOWEDIPS

        if not value:
            self.first_allowed_ip = self.last_allowed_ip = None
            return

        value = [v if isinstance(v, AllowedIP) else AllowedIP.from_ip_network(v) for v in value]

        self.first_allowed_ip = value[0]
        self.last_allowed_ip = value[-1]

        if len(value) == 1:
            self.first_allowed_ip.next_allowed_ip = self.last_allowed_ip
            self.last_allowed_ip.next_allowed_ip = None
            return

        for i in range(len(value)):
            value[i].next_allowed_ip = value[i + 1] if i + 1 < len(value) else None

    def __eq__(self, other):
        return (isinstance(other, WireGuardPeer) and
                addressof(self.pointer.contents) == addressof(other.pointer.contents))

    def __bool__(self):
        return bool(self._pointer)

    @staticmethod
    def from_config(
            public_key: PublicKey,
            preshared_key: PrivateKey = None,
            endpoint: WireGuardEndpoint | Tuple[str, int] = None,
            allowed_ips: List[AllowedIP | str] = None,
            persistent_keepalive_interval: int = 0,

    ):

        wgp = WireGuardPeer(cast(calloc(1, sizeof(wg_peer)), wg_peer_p))

        wgp.public_key = public_key
        if preshared_key:
            wgp.preshared_key = preshared_key
        if endpoint:
            wgp.endpoint = endpoint
        if allowed_ips:
            wgp.allowed_ips = allowed_ips
        if persistent_keepalive_interval:
            wgp.persistent_keepalive_interval = persistent_keepalive_interval
        return wgp


class WireGuardDevice:

    def __init__(self, ptr: wg_device_p = None):
        self._pointer = ptr or wg_device_p()

    @property
    def name(self):
        return self._pointer.contents.name.decode('utf8')

    @property
    def ifindex(self) -> int:
        return self._pointer.contents.ifindex

    @property
    def public_key(self) -> PublicKey:
        return PublicKey(bytes(self._pointer.contents.public_key))

    @property
    def private_key(self) -> PrivateKey:
        if not self._pointer.contents.private_key:
            raise ValueError('Private key is null')
        return PrivateKey(bytes(self._pointer.contents.private_key))

    @private_key.setter
    def private_key(self, value: PrivateKey):
        if value:
            self.flags |= WGDeviceFlags.WGDEVICE_HAS_PRIVATE_KEY | WGDeviceFlags.WGDEVICE_HAS_PUBLIC_KEY
            memmove(self._pointer.contents.private_key, value.encode(), 32)
        else:
            memset(self._pointer.contents.private_key, 0, 32)

    @property
    def flags(self) -> int:
        return self._pointer.contents.flags

    @flags.setter
    def flags(self, value):
        self._pointer.contents.flags = value

    @property
    def fwmark(self) -> int:
        return self._pointer.contents.fwmark

    @fwmark.setter
    def fwmark(self, value):
        if value:
            self.flags |= WGDeviceFlags.WGDEVICE_HAS_FWMARK
            self._pointer.contents.fwmark = value
        else:
            self.flags ^= WGDeviceFlags.WGDEVICE_HAS_FWMARK
            self._pointer.contents.fwmark = 0

    @property
    def listen_port(self) -> int:
        return self._pointer.contents.listen_port

    @listen_port.setter
    def listen_port(self, value):
        if value:
            self.flags |= WGDeviceFlags.WGDEVICE_HAS_LISTEN_PORT
            self._pointer.contents.listen_port = value
        else:
            self.flags ^= WGDeviceFlags.WGDEVICE_HAS_LISTEN_PORT
            self._pointer.contents.listen_port = 0

    @property
    def first_peer(self) -> WireGuardPeer:
        return WireGuardPeer(self._pointer.contents.first_peer)

    @first_peer.setter
    def first_peer(self, value: WireGuardPeer):
        self._pointer.contents.first_peer = value.pointer if value else None

    @property
    def last_peer(self) -> WireGuardPeer:
        return WireGuardPeer(self._pointer.contents.last_peer)

    @last_peer.setter
    def last_peer(self, value: WireGuardPeer):
        self._pointer.contents.last_peer = value.pointer if value else None

    def __del__(self):
        if self._pointer:
            wg_free_device(self._pointer)

    def add_peer(self, peer: WireGuardPeer):
        self.flags |= WGDeviceFlags.WGDEVICE_REPLACE_PEERS
        if not self.last_peer and not self.first_peer:
            self.last_peer = peer
            self.first_peer = peer
            peer.next_peer = None
        else:
            self.last_peer.next_peer = peer
            self.last_peer = peer

    def save(self):
        wg_set_device(self._pointer.contents)

    @property
    def peers(self):
        if not self.first_peer:
            yield from ()
            return

        current = self.first_peer
        yield current

        while current != self.last_peer:
            current = current.next_peer
            if not current:
                break
            yield current

    @peers.setter
    def peers(self, value: List[WireGuardPeer]):
        self.flags |= WGDeviceFlags.WGDEVICE_REPLACE_PEERS

        if not value:
            self.first_peer = self.last_peer = None
            return

        self.first_peer = value[0]
        self.last_peer = value[-1]

        if len(value) == 1:
            self.first_peer.next_peer = self.last_peer
            self.last_peer.next_peer = None
            return

        for i in range(len(value)):
            value[i].next_peer = value[i + 1] if i + 1 < len(value) else None


def list_device_names() -> List[str]:
    buf = wg_list_device_names()
    b = []
    i = 0
    last_byte = -1

    while True:
        c = buf[i]
        if not c and (not last_byte or not i):
            break
        b.append(c)
        last_byte = c
        i += 1

    libc.free(buf)

    return [d.decode('utf8') for d in bytes(b).rstrip(b'\x00').split(b'\x00')]


def del_device(device: WireGuardDevice | str) -> None:
    if isinstance(device, WireGuardDevice):
        device = device.name
    wg_del_device(bytes(device, 'utf8'))


def add_device(device) -> WireGuardDevice:
    wg_add_device(bytes(device, 'utf8'))
    return get_device(device)


def get_device(device: WireGuardDevice | str) -> WireGuardDevice:
    if isinstance(device, WireGuardDevice):
        device = device.name
    dev = wg_device_p()
    wg_get_device(byref(dev), bytes(device, 'utf8'))
    return WireGuardDevice(dev)


def generate_private_key() -> PrivateKey:
    secret = bytearray(random(PrivateKey.SIZE))
    secret[0] &= 248
    secret[31] = (secret[31] & 127) | 64
    return PrivateKey(secret)


def generate_preshared_key() -> PrivateKey:
    return PrivateKey.generate()

