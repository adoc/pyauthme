from __future__ import absolute_import



import pyramid.authentication


try:
    range = xrange
except NameError:
    pass # P1y3 already.


try:
    import cryptu.hash
    hashalg = cryptu.hash.shash

except ImportError:
    logger.warning("`cryptu` is unavailable. Using less secure hash "
                   "function.")
    import hashlib
    hashalg = hashlib.sha512


class TktAuthnPolicy(pyramid.authentication.AuthTktAuthenticationPolicy):
    """
    """

    def __init__(self, secret, **kwa):
        """(secret, callback=None, cookie_name='auth_tkt', secure=False,
            include_ip=False, timeout=None, reissue_time=None, max_age=None,
            path='/', http_only=False, wild_domain=True, debug=False,
            hashalg=<object object at 0x7f5fb68f1bc0>, parent_domain=False,
            domain=None)
        """
        kwa['callback'] = self._policy_callback
        kwa['hashalg'] = kwa.get('hashalg', hashalg)
        pyramid.authentication.AuthTktAuthenticationPolicy.__init__(secret, kwa)

    def _policy_callback(self, userid):
        # Check if the user exists.
        pass

    def remember(self, request, principal, **kwa):
        # Do stuffs.
        return pyramid.authentication.AuthTktAuthenticationPolicy.remember(
            request, principal, **kwa)

    