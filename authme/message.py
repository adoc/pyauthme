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
        #body = self.cipher.encrypt(authme.codecs.JsonArgCodec.encode(self.payload))
        body = self._cipher.encrypt(self.payload)
        signature = self._signer.sign(body, self._cipher.iv, *tuple(self.signing_params))
        return body, self._cipher.iv, signature
        #      ctext, nonce, signature

    def receive(self, body, nonce, signature):
        if self._signer.verify(signature, body, nonce, *self.signing_params) is True:
            #self.payload = authme.codecs.JsonArgCodec.decode(
            #                    self.cipher.decrypt(ctext))
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


class Message_old:
    """
    """
    def __init__(self, signer=None, cipher=None):
        """
        `signer` exposes .sign and .verify.
        `cipher` exposes .encrypt and .decrypt
        """
        self.signer = signer or PassSigner
        self.cipher = cipher or PassCipher

    def __type_check(self, payload, *args):
        if not isinstance(payload, bytes):
            raise TypeError("`payload` must be bytes.")
        for arg in args:
            if arg and not isinstance(arg, bytes):
                raise TypeError("Additional signer args must be bytes.")


    def send(self, payload, *signing_params):
        """
        Prepare a message for sending.
        Returns cipher_text and signature.
        """
        self.__type_check(payload, *signing_params)

        payload, *signing_params = self.wrapper.pre_send(payload,
                                                         *signing_params)

        payload = self.cipher.encrypt(payload)
        
        return self.wrapper.post_send(payload, self.signer.sign(payload,
                                                            *signing_params))

    def receive(self, payload, challenge, *signer_params):
        """
        Process a received message.
        """
        self.__type_check(payload, challenge, *signer_params)

        payload, challenge, *signer_params = self.wrapper.pre_receive(payload,
                                                    challenge, *signer_params)

        if not self.signer.verify(challenge, payload, *signer_params):
            raise NotImplementedError('Signature failed but signer didnt throw'
                                        'an error.')
        payload = self.cipher.decrypt(payload)

        return self.wrapper.post_receive(payload)



class AuthnMessage:
    """
    """
    def __init__(self, signer_cls, cipher_cls=None, wrapper=None,
                 random_func=random_func):
        self.signer_cls = signer_cls
        self.cipher_cls = cipher_cls
        self.wrapper = wrapper
        self.random_func = random_func or os.urandom

    def send(self, secret, payload, *signing_params, **kwa):
        cipher_key = kwa.get('key')
        nonce = kwa.get('nonce', self.random_func(16))

        cipher = self.cipher_cls and self.cipher_cls(cipher_key, nonce)
        message = Messaging(signer=self.signer_cls(signing_secret),
                          cipher=cipher, wrapper=self.wrapper)

        return (nonce,) + message.send(payload, nonce, *signing_params)


def NonePass(*args, **kwa):
    """Dummy object.
    """
    return None


class _Message(object):
    """Just a simple packaging for messages that will hook in a `signer` and
    a `cipher`.

    `wrapper` must expose .pre_send, .post_send, .pre_receive and .post_receive
    `signer` must expose .sign and .verify
    `cipher` must expose .encrypt and .decrypt
    """
    def __init__(self, wrapper=None, signer=None, cipher=None):
        self.wrapper = wrapper
        self.signer = signer
        self.cipher = cipher

    def wrapped(func):
        """Decorator to hook `wrapper` methods before and after decorated function.
        """
        def _inner(self, *args):
            if self.wrapper:
                # print(func.__name__)
                if func.__name__=='send':
                    pre = self.wrapper.pre_send
                    post = self.wrapper.post_send
                else:
                    pre = self.wrapper.pre_receive
                    post = self.wrapper.post_receive

                #print(args)
                pre_return = pre(*args)
                #print(pre_return)
                func_return = func(self, *pre_return)
                #print(func_return)
                return post(*func_return)
            else:
                return func(self, *args)
        return _inner

    @wrapped
    def send(self, payload, *args):
        """
        Prepare a message for sending.
        """
        if self.cipher:
            payload = self.cipher.encrypt(payload)
        if self.signer:
            signature = self.signer.sign(payload, *args)
            return payload, signature
        return (payload,)

    @wrapped
    def receive(self, payload, challenge, *args):
        """
        Process a received message.
        """
        print("receive")
        print(payload, challenge, args)
        if self.signer and not self.signer.verify(challenge, payload, *args):
            raise NotImplementedError('Signature failed but signer didnt throw'
                                        'an error.')
        if self.cipher:
            return (self.cipher.decrypt(payload),)
        else:
            return (payload,)


class JsonWrapper(object):
    def __init__(self, json=authme.codecs.json):
        self._json = json

    def pre_send(self, payload, *args):
        payload = self._json.dumps(payload).encode()
        return (payload,) + args

    def post_send(self, payload, challenge, *args):
        try:
            payload = payload.decode()
        except UnicodeDecodeError:
            payload = b64encode(payload)
        return (payload, b64encode(challenge)) + args

    def pre_receive(self, payload, challenge, *args):
        payload = self._json.dumps(payload).encode()
        #try:
        #    payload = payload.encode()
        #except AttributeError:
        #    payload = b64decode(payload)

        return (payload, b64decode(challenge)) + args

    def post_receive(self, payload):
        return self._json.loads(payload.decode())



class AuthApi(object):
    """
    """
    def __init__(self, sender_id, remotes=Remotes(), message_wrapper=NonePass,
                    signer_cls=authme.hmac.TimedHmac, cipher_cls=NonePass,
                    time_provider=authme.hmac.time_provider):
        """
        """
        self.sender_id = sender_id
        if isinstance(remotes, Remotes):
            self.remotes = remotes
        else:
            self.remotes = Remotes(remotes)
        self._message_wrapper = message_wrapper
        self._signer_cls = signer_cls
        self._cipher_cls = cipher_cls
        self.time_provider = time_provider

    def add_remote(self, remote_id, value):
        self.remotes.update(remote_id.encode(), value)

    def remove_remote(self, remote_id):
        self.remotes.remove(remote_id.encode())

    def send(self, remote_id, payload, *args):
        """
        """
        remote = self.remotes.get(remote_id)
        secret = remote['secret']
        key = remote['key']

        #nonce = base64.b64encode(os.urandom(16))
        nonce = os.urandom(16)

        wrapper = self._message_wrapper()
        signer = self._signer_cls(secret, time_provider=self.time_provider)
        cipher = self._cipher_cls(key, nonce)

        message = Messaging(wrapper=wrapper, signer=signer, cipher=cipher)

        return (nonce,) + message.send(payload, self.sender_id, nonce, *args)
        

    def receive(self, remote_id, nonce, challenge, payload, *args, expiry=600):
        """
        """
        remote = self.remotes.get(remote_id)
        secret = remote['secret']
        key = remote['key']

        wrapper = self._message_wrapper()
        signer = self._signer_cls(secret, expiry=expiry)
        cipher = self._cipher_cls(key, nonce)

        message = Messaging(wrapper=wrapper, signer=signer, cipher=cipher)

        return message.receive(payload, challenge, remote_id, nonce, *args)
        

class JsonAuthApi(AuthApi):
    """
    """
    def __init__(self, *args, **kwa):
        #kwa['message_wrapper'] = JsonWrapper
        AuthApi.__init__(self, *args, **kwa)

    def send(self, remote_id, payload, *args):
        """
        """
        nonce, payload, signature = AuthApi.send(self, remote_id, payload,
                                                    *args)

        #nonce = b64encode(nonce)
        return {'sender_id': self.sender_id, 'nonce': nonce, 'payload': payload, 'signature': signature}

    def receive(self, packet, *args, expiry=600):
        """
        """
        print(packet)
        return AuthApi.receive(self, packet['sender_id'], packet['nonce'], packet['signature'],
                                packet['payload'], *args, expiry=expiry)