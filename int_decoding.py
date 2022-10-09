from base64 import urlsafe_b64encode

from rlp import encode

if __name__ == '__main__':
    """
    rlp_decoder f884b8407098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c01826964827634826970847f00000189736563703235366b31a103ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd31388375647082765f
    [
        "0x7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c",
        "0x01",
        "0x6964",
        "0x7634",
        "0x6970",
        "0x7f000001",
        "0x736563703235366b31",
        "0x03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138",
        "0x756470",
        "0x765f"
    ]
    """
    seq = bytes.fromhex('0001')  # replaces 0x01 with 0x0001
    rlp_data = encode(
        [
            0x7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c,
            seq, 'id', 'v4', 'ip', 0x7f000001, 'secp256k1', bytes.fromhex(
            '03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138'), 'udp', 0x765f])
    textual_form = "enr:" + urlsafe_b64encode(rlp_data).decode('utf-8').rstrip('=')
    print(textual_form)
    # enr:-Ia4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5yCAAGCaWSCdjSCaXCEfwAAAYlzZWNwMjU2azGhA8pjTK4NSay0Adikxrb-jFW3DRFb9AB2nMFADzJYzTE4g3VkcIJ2Xw

    seq = bytes.fromhex('000001')  # replaces 0x01 with 0x0001
    rlp_data = encode(
        [
            0x7098ad865b00a582051940cb9cf36836572411a47278783077011599ed5cd16b76f2635f4e234738f30813a89eb9137e3e3df5266e3a1f11df72ecf1145ccb9c,
            seq, 'id', 'v4', 'ip', 0x7f000001, 'secp256k1', bytes.fromhex(
            '03ca634cae0d49acb401d8a4c6b6fe8c55b70d115bf400769cc1400f3258cd3138'), 'udp', 0x765f])
    textual_form = "enr:" + urlsafe_b64encode(rlp_data).decode('utf-8').rstrip('=')
    print(textual_form)
    # enr:-Ie4QHCYrYZbAKWCBRlAy5zzaDZXJBGkcnh4MHcBFZntXNFrdvJjX04jRzjzCBOonrkTfj499SZuOh8R33Ls8RRcy5yDAAABgmlkgnY0gmlwhH8AAAGJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCdl8