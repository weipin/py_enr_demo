from base64 import urlsafe_b64encode
from hashlib import sha256

from ecdsa import SigningKey, SECP256k1
from ecdsa.util import sigencode_string_canonize
from eth_hash.auto import keccak
from rlp import encode

if __name__ == '__main__':
    """Builds Ethereum Node Records.
    
    Demonstrates how to specify additional data when creating a deterministic ECDSA signature.
    
    Uses the example record from the ENR spec:
    https://github.com/ethereum/devp2p/blob/master/enr.md
    """
    key = SigningKey.from_secret_exponent(
        0xb71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291, curve=SECP256k1)

    # Builds content RLP
    rlp_data = encode([1, 'id', 'v4', 'ip', 0x7f000001, 'secp256k1', bytes.fromhex(
        '03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138'), 'udp', 0x765f])
    rlp_data_hash = keccak(rlp_data)

    # First, we sign the content RLP **without** additional data.
    # So we can verify the resulting value against the test vector from the spec,
    # ensuring this script itself is functioning correctly.
    #
    # `sigencode_string_canonize` enforces "low-s value".
    content_signature = key.sign_digest_deterministic(rlp_data_hash, hashfunc=sha256,
                                                      sigencode=sigencode_string_canonize)
    rlp_with_signature = encode(
        [content_signature, 1, 'id', 'v4', 'ip', 0x7f000001, 'secp256k1', bytes.fromhex(
            '03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138'), 'udp', 0x765f])
    textual_form = "enr:" + urlsafe_b64encode(rlp_with_signature).decode('utf-8').rstrip('=')
    print(textual_form)
    # Check `textual_form` against the spec
    # enr:-IS4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5wBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8

    # Now we sign the content RLP **with** additional data.
    # While the data can be any random 32 bytes, we choose "0xbaaaaaad..." for testing purposes.
    additional_data = bytes.fromhex(
        'baaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaadbaaaaaad')
    content_signature = key.sign_digest_deterministic(rlp_data_hash, hashfunc=sha256,
                                                      sigencode=sigencode_string_canonize,
                                                      extra_entropy=additional_data)
    rlp_with_signature = encode(
        [content_signature, 1, 'id', 'v4', 'ip', 0x7f000001, 'secp256k1', bytes.fromhex(
            '03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138'), 'udp', 0x765f])
    textual_form = "enr:" + urlsafe_b64encode(rlp_with_signature).decode('utf-8').rstrip('=')
    print(textual_form)
    # enr:-IS4QLJYdRwxdy-AbzWC6wL9ooB6O6uvCvJsJ36rbJztiAs1JzPY0__YkgFzZwNUuNhm1BDN6c4-UVRCJP9bXNCmoDYBgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8
