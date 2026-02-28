from overtun.sshtools.utils import get_pkey_from_pem, get_pem_from_pkey, generate_key
from paramiko import Ed25519Key, RSAKey, ECDSAKey


def test_get_pkey_from_pem(private_rsa_pem, private_ecdsa_pem, private_ed25519_pem):
    pkey = get_pkey_from_pem(private_rsa_pem)
    assert isinstance(pkey, RSAKey)

    pkey = get_pkey_from_pem(private_ecdsa_pem)
    assert isinstance(pkey, ECDSAKey)

    pkey = get_pkey_from_pem(private_ed25519_pem)
    assert isinstance(pkey, Ed25519Key)


def test_generate_key():
    pkey = generate_key(Ed25519Key)
    assert pkey

    pkey = generate_key(RSAKey)
    assert pkey

    pkey = generate_key(ECDSAKey)
    assert pkey


def test_get_pem_from_pkey(private_rsa_pem, private_ecdsa_pem, private_ed25519_pem):
    pkey = get_pkey_from_pem(private_rsa_pem)
    pem = get_pem_from_pkey(pkey)
    assert get_pkey_from_pem(pem) == pkey

    pkey = get_pkey_from_pem(private_ecdsa_pem)
    pem = get_pem_from_pkey(pkey)
    assert get_pkey_from_pem(pem) == pkey

    pkey = get_pkey_from_pem(private_ed25519_pem)
    pem = get_pem_from_pkey(pkey)
    assert get_pkey_from_pem(pem) == pkey
