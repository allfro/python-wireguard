import wireguard as wg

device = wg.add_device('test0')

pub = wg.PublicKey(wg.random(32))
psk = wg.PrivateKey.generate()
device.private_key = wg.generate_private_key()
device.add_peer(
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

device.save()