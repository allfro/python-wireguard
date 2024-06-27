from wireguard import random, generate_private_key, PrivateKey, PublicKey, WireGuardPeer, add_device

device = add_device('test0')

pub = PublicKey(random(32))
psk = PrivateKey.generate()
device.private_key = generate_private_key()
device.add_peer(
    WireGuardPeer.from_config(
        pub,
        psk,
        ('fe08::1', 443),
        [
            '192.168.0.0/24', 'fe08::/24'
        ],
        21
    )
)

device.save()