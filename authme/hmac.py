"""
whmac.py3
Convenient HMAC wrappers.


Author: github.com/adoc
Location: https://gist.github.com/adoc/8552289

"""

import time
import hashlib
import hmac
import authme.exc


def time_provider():
    return int(time.time())


def int_to_bytes(n):
    """Converts an integer to bytes."""
    # inspired by http://stackoverflow.com/a/3547409 but updated for py3
    result = bytearray()
    while n:
        result.insert(0, n & 0xFF)
        n >>= 8
    return result


def bytes_to_int(b):
    """Converts bytes to an integer."""
    # My own implementation. can probably be cleaned up/improved.
    n = 0
    blen = len(b)
    for i in range(blen):
        n += b[blen-i-1] << 8 * i
    return n


def rstrip_bytes(b):
    for i in reversed(range(len(b))):
        if b[i] != 0:
            break
    return b[:i+1]


class Hmac(object):
    """
    """
    def __init__(self, secret, passes=1, hashalg=hashlib.sha256):
        """Initialize HmacClient object.

        secret          str         hmac secret.
        passes          int         number of hmac update passes to use.
        hashalg         obj         hash algorythm.
        encoding        str         encoding to use on input variables.
        """
        self.__secret = secret
        self.__passes = passes
        self.__hashalg = hashalg

    def sign(self, *args):
        # Rely on the alg for key stretching. Not in this scope.
        """HMAC that uses multiple passes for key stretching.

        *args       arglist     arguments to be hashed
        returns     bstr        bytestring digest hash.
        """
        h = hmac.new(self.__secret, None, self.__hashalg)

        for _ in range(self.__passes):
            for arg in args:
                if arg:
                    h.update(arg)

        return h.digest()

    def challenge(self, challenge, *args):
        return challenge == self.sign(*args)

    def verify(self, sig, *args):
        """Verifies HMAC signature by rehashing *args.

        sig     bstr        bytestring challenge signature.
        *args   arglist     arguments to be hashed.

        returns boolean     True or raises SignatureBad exception.
        """
        if self.challenge(sig, *args):
            return True
        else:
            raise authme.exc.SignatureBad("Incorrect HMAC challenge.")


class TimedHmac(Hmac):
    """
    """
    def __init__(self, secret, passes=1, hashalg=hashlib.sha256,
                    expiry=60, time_provider=time_provider):
        """Initialize TimedHmac object.

        secret          str         hmac secret.
        passes          int         number of hmac update passes to use.
        hashalg         obj         hash algorythm.
        expiry          int         number of seconds to expire signature.
        time_provider   func        function to get current integer time.
        encoding        str         encoding to use on input variables.
        """
        Hmac.__init__(self, secret, passes, hashalg)
        self._expiry = expiry
        self._time_provider = time_provider

    def sign(self, *args):
        """HMAC that hashes the timestamp and multiple
        passes for key stretching.

        *args   arglist     arguments to be hashed.
        """
        ts = str(self._time_provider()).encode()
        digest = Hmac.sign(self, ts, *args)
        return digest + ts

    def challenge(self, challenge, *args):
        """
        """
        challenge = rstrip_bytes(challenge)
        sig, ts = challenge[:-10], int(challenge[-10:].decode())
        now = self._time_provider()
        delta = now - ts

        if abs(delta) > self._expiry:
            raise authme.exc.SignatureTimeout("Signature it too old.")

        chal = Hmac.sign(self, str(ts).encode(), *args)
        return sig == chal