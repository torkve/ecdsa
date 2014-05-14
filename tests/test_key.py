__author__ = 'torkve'

from ecdsa import Key
from unittest import TestCase, main


class TestKey(TestCase):
    keys = [
        (
            'ecdsa-sha2-nistp256',
            '8d:15:fa:76:0f:72:31:77:b0:97:3b:81:2c:03:61:c5',
            'AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA6/wwHUzKeZfItFQ1RO1kakNekqiPOWHXNZFBPRODrTDsLN2OqfMQi/PXztyuATJpvBvQ/k2SdOUHGe3giMwR0=',
            '-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIGo9RCb3vc8p0+2malIeoxIDSTs0wwJodN29ROuLeSotoAoGCCqGSM49\nAwEHoUQDQgAEDr/DAdTMp5l8i0VDVE7WRqQ16SqI85Ydc1kUE9E4OtMOws3Y6p8x\nCL89fO3K4BMmm8G9D+TZJ05QcZ7eCIzBHQ==\n-----END EC PRIVATE KEY-----\n'
        ),
        (
            'ecdsa-sha2-nistp384',
            '79:12:a5:9e:6b:2e:ad:3d:18:75:91:d9:60:de:b3:03',
            'AAAAE2VjZHNhLXNoYTItbmlzdHAzODQAAAAIbmlzdHAzODQAAABhBIt/66lwRmxrXlFWWx9FS2locf1mFqfpanzrJIMR/v888DAdpi9boDCo/y4PdzKtWW8ckCF3fzn9XjuCU3qSRFDpLIGHXLCf5LdWAEoJEzXMEKctjhJTvKJ+GiLFPE8AvA==',
            '-----BEGIN EC PRIVATE KEY-----\nMIGkAgEBBDBm+CgxXAPvd4xFnbiIJpZmPYwujRiWVJmNE/+iWBwX+GHMjBmTV+XM\n9t0g6n5v1EmgBwYFK4EEACKhZANiAASLf+upcEZsa15RVlsfRUtpaHH9Zhan6Wp8\n6ySDEf7/PPAwHaYvW6AwqP8uD3cyrVlvHJAhd385/V47glN6kkRQ6SyBh1ywn+S3\nVgBKCRM1zBCnLY4SU7yifhoixTxPALw=\n-----END EC PRIVATE KEY-----\n'
        ),
        (
            'ecdsa-sha2-nistp521',
            '17:56:36:6f:55:a3:36:0b:88:e4:e2:bd:5c:d5:3d:a9',
            'AAAAE2VjZHNhLXNoYTItbmlzdHA1MjEAAAAIbmlzdHA1MjEAAACFBAFjioovPo4sxBLwpnAcLb1o47m/71/n5i8xOvyoR0AKUKFld2CwOgwuewTB3pNBMK6ZdHAwO4ZUGQU9GeoWcjkhUgCmk9vugCer8nVOi79MRP49Ng4PmsUgx+mEgG4kDtWeJGqyMxLhTdFUoZceGCxz8XwT/WG+JqiUXCkRAwXA3DZyCA==',
            '-----BEGIN EC PRIVATE KEY-----\nMIHbAgEBBEF5pjg70oUozcOrn02mIBRN8OqpJTmewKiH5iPFZ1V7ApMU4//yzhEd\nWAV/TrxuzZomraqCp2qATsxTcnCa0nqQXKAHBgUrgQQAI6GBiQOBhgAEAWOKii8+\njizEEvCmcBwtvWjjub/vX+fmLzE6/KhHQApQoWV3YLA6DC57BMHek0Ewrpl0cDA7\nhlQZBT0Z6hZyOSFSAKaT2+6AJ6vydU6Lv0xE/j02Dg+axSDH6YSAbiQO1Z4karIz\nEuFN0VShlx4YLHPxfBP9Yb4mqJRcKREDBcDcNnII\n-----END EC PRIVATE KEY-----\n'
        ),
    ]

    def test_serialize(self):
        for curve, fp, pub, priv in self.keys:
            fp = ''.join(x.decode('hex') for x in fp.split(':'))

            key = Key.from_string(priv)
            self.assertEquals(key.nid_name(), curve)
            self.assertEquals(key.to_pem(), priv)
            self.assertEquals(key.to_ssh(), pub)
            self.assertTrue(key.has_private())
            self.assertEquals(key.fingerprint(), fp)

            key = Key.from_pem(priv)
            self.assertEquals(key.nid_name(), curve)
            self.assertEquals(key.to_pem(), priv)
            self.assertEquals(key.to_ssh(), pub)
            self.assertTrue(key.has_private())
            self.assertEquals(key.fingerprint(), fp)

            self.assertRaises(ValueError, Key.from_ssh, priv)

            key = Key.from_string(pub)
            self.assertEquals(key.nid_name(), curve)
            self.assertEquals(key.to_ssh(), pub)
            self.assertRaises(ValueError, key.to_pem)
            self.assertFalse(key.has_private())
            self.assertEquals(key.fingerprint(), fp)

            key = Key.from_ssh(pub)
            self.assertEquals(key.nid_name(), curve)
            self.assertEquals(key.to_ssh(), pub)
            self.assertRaises(ValueError, key.to_pem)
            self.assertFalse(key.has_private())
            self.assertEquals(key.fingerprint(), fp)

            self.assertRaises(ValueError, Key.from_pem, pub)

    def test_generate(self):
        for bits in (256, 384, 521):
            key = Key.generate(bits)
            self.assertTrue(key.has_private())
            self.assertEquals(key.bits(), bits)

    def test_sign(self):
        data = 'kekeke'
        for curve, fp, pub, priv in self.keys:
            signKey = Key.from_string(priv)
            verifyKey = Key.from_string(pub)

            sign = signKey.sign(data)
            self.assertRaises(ValueError, verifyKey.sign, data)

            self.assertTrue(signKey.verify(data, sign))
            self.assertTrue(verifyKey.verify(data, sign))

            self.assertFalse(signKey.verify(data * 2, sign))
            self.assertFalse(verifyKey.verify(data * 2, sign))


if __name__ == '__main__':
    raise SystemExit(main())
