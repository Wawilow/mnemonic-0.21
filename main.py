import binascii
import base58
import hashlib


PBKDF2_ROUNDS = 2048


def to_eth_seed(mnemonic: str, passphrase: str = "") -> bytes:
    passphrase = "mnemonic" + passphrase
    mnemonic_bytes = mnemonic.encode("utf-8")
    passphrase_bytes = passphrase.encode("utf-8")
    stretched = hashlib.pbkdf2_hmac(
        "sha512", mnemonic_bytes, passphrase_bytes, PBKDF2_ROUNDS
    )
    return stretched[:32]


def to_ton_seed(mnemonic: str, passphrase: str = "") -> bytes:
    passphrase = "mnemonic" + passphrase
    mnemonic_bytes = mnemonic.encode("utf-8")
    passphrase_bytes = passphrase.encode("utf-8")
    stretched = hashlib.pbkdf2_hmac(
        "sha512", mnemonic_bytes, passphrase_bytes, PBKDF2_ROUNDS
    )
    return stretched[:128]


def to_btc_seed(mnemonic: str, passphrase: str = "") -> str:
    passphrase = "" + passphrase
    mnemonic_bytes = mnemonic.encode("utf-8")
    passphrase_bytes = passphrase.encode("utf-8")
    stretched = hashlib.pbkdf2_hmac(
        "sha256", mnemonic_bytes, passphrase_bytes, PBKDF2_ROUNDS
    )

    master_key = stretched.hex().upper()

    def wif(masterkey):
        var80 = "80"+masterkey
        var = hashlib.sha256(
            binascii.unhexlify(
                hashlib.sha256(
                    binascii.unhexlify(var80)
                ).hexdigest()
            )
        ).hexdigest()
        return str(base58.b58encode(binascii.unhexlify(str(var80) + str(var[0:8]))), 'utf-8')

    return wif(master_key)


seed = "12345 12345 12345 12345 12345 12345 12345 12345 12345"
pk = to_eth_seed(seed)
eth_s_key = "0x" + pk.hex()
print("eth: ", eth_s_key)
# result
# 0xc5d5412349d66733f3beef726f2932290e711fd541d55c564030808365584ae3

btc_wif = to_btc_seed(seed)
print("btc wif: ", btc_wif)
# result
# 5KfSmEhzpWHFP5DMzbxMxNr45tUXehebZufCzFXQpSiFRC7hwo7

ton_pk = to_ton_seed(seed).hex()
print("ton: ", ton_pk)
# result
# c5d5412349d66733f3beef726f2932290e711fd541d55c564030808365584ae357026a4b234d9b8f2be22c10c181f33494503f88af3573f21572006fb49ea8d1
