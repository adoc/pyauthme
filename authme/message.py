"""
Several Messaging classes, building blocks and helpers.

Author: github.com/adoc

"""
import os

import uuid

import authme.hmac
import authme.exc
import authme.codecs


random_func = None
try:
    import cryptu.random
except NameError:
    pass
else:
    random_func = cryptu.random.read


class Remotes(object):
    """

    get
    update
    remove
    """
    # more or less a "defaultdict"? refactor?
    __default_remote = {'secret': None,
                        'key': None,
                        'tight': False}

    def __init__(self, remotes={}, random_id_func=uuid.uuid4):
        self.random_id_func = random_id_func

        self._remotes = {}
        for k, v in remotes.items():
            self.update(k, v)

    def add(self, id=None, vals={}):
        if not id:
            id = self.random_id_func()
        return id, self.update(id, vals)

    def get(self, id_):
        if not id_ in self._remotes:
            raise authme.exc.MessageClientBad("Remote id %s is not a valid "
                                              "client." % id_)
        return self._remotes[id_]

    def update(self, id_, val):
        remote = self.__default_remote.copy()
        remote.update(val)
        self._remotes.update({id_: remote})
        return remote

    def remove(self, id_):
        if not id_ in self._remotes:
            raise authme.exc.MessageClientBad("Remote id %s is not a valid "
                                              "client." % id_)
        del self._remotes[id_]

    def __contains__(self, id_):
        return id_ in self._remotes


class PassSigner:
    @classmethod
    def sign(cls, val, *args):
        return None

    @classmethod
    def verify(cls, val, *args):
        return True


class PassCipher:
    iv = None
    @classmethod
    def encrypt(cls, val):
        if isinstance(val, str):
            return val.encode()
        else:
            return val

    @classmethod
    def decrypt(cls, val):
        return val


class PassWrapper:
    @classmethod
    def pre_send(cls, *args):
        return args

    @classmethod
    def post_send(cls, *args):
        return args

    @classmethod
    def pre_receive(cls, *args):
        return args

    @classmethod
    def post_receive(cls, payload):
        return payload


class Message:
    """Message state object.
    """
    def __init__(self, payload=None, signer=None, signing_params=None, cipher=None):
        """
        """
        self._payload = payload
        self._signer = signer or PassSigner
        self._signing_params = signing_params or ()
        self._cipher = cipher or PassCipher

        setattr(self.__class__, 'payload', property(self.__class__.get_payload,
                                                    self.__class__.set_payload))
        setattr(self.__class__, 'signing_params', property(
                                                    self.__class__.get_signing_params,
                                                    self.__class__.set_signing_params))

    def get_payload(self):
        """
        """
        return self._payload

    def set_payload(self, value):
        """
        """
        assert isinstance(value, bytes), "`payload` requires bytes."
        self._payload = value

    def get_signing_params(self):
        return self._signing_params

    def set_signing_params(self, value):
        assert isinstance(value, tuple), "`signing_params` requires a tuple value."
        self._signing_params = value

    def send(self):
        body = self._cipher.encrypt(self.payload)
        signature = self._signer.sign(body, self._cipher.iv, *tuple(self.signing_params))
        return body, self._cipher.iv, signature
        #      ctext, nonce, signature

    def receive(self, body, nonce, signature):
        if self._signer.verify(signature, body, nonce, *self.signing_params) is True:
            payload = self._cipher.decrypt(body)
            if payload:
                self.payload = payload
                return self._payload
            else:
                raise NotImplementedError('Cipher failed to decrypt body.')
        else:
            raise NotImplementedError('Signature failed but signer didnt throw'
                                        'an error.')


class JsonMessage(Message):
    def get_payload(self):
        return authme.codecs.JsonArgCodec.encode(self._payload)[0].encode()

    def set_payload(self, value):
        self._payload = authme.codecs.JsonArgCodec.decode(value)[0]

    def get_signing_params(self):
        return authme.codecs.encode_all(
                    authme.codecs.JsonArgCodec.encode(*self._signing_params))