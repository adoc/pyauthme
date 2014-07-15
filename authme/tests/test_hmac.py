import unittest
import authme.hmac

class HmacTests(unittest.TestCase):
    """
    """
    def test_hmac(self):
        h = authme.hmac.Hmac(b'12345')
        a = h.sign(b'1',b'2',b'3')
        self.assertTrue(h.verify(a, b'1', b'2', b'3'))

        h = authme.hmac.TimedHmac(b'12345', expiry=1)
        a = h.sign(b'1', b'2', b'3')
        self.assertTrue(h.verify(a, b'1', b'2', b'3'))