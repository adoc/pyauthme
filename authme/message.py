"""
Several Messaging classes, building blocks and helpers.

Author: github.com/adoc

"""
import os
import base64
import json as _json
import functools
import collections
import whmac


# Don't really need these anymore.
b64encode = lambda t: base64.b64encode(t)
b64decode = lambda t: base64.b64decode(t)


# http://stackoverflow.com/a/13520518
class DotDict(dict):
    """
    a dictionary that supports dot notation 
    as well as dictionary access notation 
    usage: d = DotDict() or d = DotDict({'val1':'first'})
    set attributes: d.val2 = 'second' or d['val2'] = 'second'
    get attributes: d.val2 or d['val2']
    """
    __getattr__ = dict.__getitem__
    __setattr__ = dict.__setitem__
    __delattr__ = dict.__delitem__

    def __init__(self, dct={}):
        for key, value in dct.items():
            if hasattr(value, 'keys'):
                value = DotDict(value)
            self[key] = value


json = DotDict()
# Provides consistency for serialization/hashing.
json.dumps = functools.partial(_json.dumps, separators=(',', ':'))
json.loads = functools.partial(_json.loads,
                                object_pairs_hook=collections.OrderedDict)


# Exceptions
# ==========
class AuthException(Exception):
    """
    Base message authentication exception.
    """
    pass


class ClientBad(AuthException):
    """
    Client wasn't found in the data model.
    """
    pass


def NonePass(*args, **kwa):
    """
    Dummy object.
    """
    return None


class Message(object):
    """
    Just a simple packaging for messages that will hook in a `signer` and
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
        """
        Decorator to hook `wrapper` methods before and after decorated function.
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
        if self.signer and not self.signer.verify(challenge, payload, *args):
            raise NotImplementedError('Signature failed but signer didnt throw'
                                        'an error.')
        if self.cipher:
            return (self.cipher.decrypt(payload),)
        else:
            return (payload,)


class JsonWrapper(object):
    def __init__(self, json=json):
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


Remote = {'secret': None,
            'key': None,
            'tight': False }

class Remotes(object):
    """

    get
    update
    remove
    """
    def __init__(self, remotes=None):
        _remotes = remotes or {}
        for k,v in _remotes.items():
            remote = Remote.copy()
            remote.update(v)
            _remotes[k] = remote
        self._remotes = _remotes
        print (self._remotes)


    def get(self, id_):
        if not id_ in self._remotes:
            raise ClientBad("Remote id %s is not a valid client." % id_)

        return self._remotes[id_]

    def update(self, id_, val):
        remote = Remote.copy()
        remote.update(val)
        self._remotes.update({id_: remote})

    def remove(self, id_):
        if not id_ in self._remotes:
            raise ClientBad("Remote id %s is not a valid client." % id_)

        del self._remotes[id_]


    def __contains__(self, id_):
        return id_ in self._remotes


class AuthApi(object):
    """
    """
    def __init__(self, sender_id, remotes=Remotes(), message_wrapper=NonePass,
                    signer_cls=whmac.TimedHmac, cipher_cls=NonePass, time_provider=whmac.time_provider):
        """
        """
        self.sender_id = sender_id
        self.remotes = remotes
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

        nonce = base64.b64encode(os.urandom(16))

        wrapper = self._message_wrapper()
        signer = self._signer_cls(secret, time_provider=self.time_provider)
        cipher = self._cipher_cls(key, nonce)

        message = Message(wrapper=wrapper, signer=signer, cipher=cipher)

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

        message = Message(wrapper=wrapper, signer=signer, cipher=cipher)

        return message.receive(payload, challenge, remote_id, nonce, *args)
        

class JsonAuthApi(AuthApi):
    """
    """
    def __init__(self, *args, **kwa):
        kwa['message_wrapper'] = JsonWrapper
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
        
        return AuthApi.receive(self, packet['sender_id'].encode(), packet['nonce'].encode(), packet['signature'],
                                packet['payload'], *args, expiry=expiry)


# Just convenient to include the tests here for now.
import unittest

class TestMessage(unittest.TestCase):

    def test_temporary_message(self):
        # Not a real test, just some dev code.
        import message
        import aes
        import whmac

        a = message.Message(signer=whmac.TimedHmac(b'12345', expiry=1),
                                cipher=aes.Aes(*aes.gen_keyiv()))

        msg = b'a'
        payload, sig = a.send(msg)
        assert a.receive(payload, sig)

    def test_temporary_auth_api(self):
        # Not a real test, just some dev code.
        import message
        import aes

        a = message.AuthApi(b'server1',
                            {b'client1': ('12345678901234567890123456789012',
                                        '12345678901234567890123456789012')})

        b = message.AuthApi(b'client1',
                            {b'server1': ('12345678901234567890123456789012',
                                        '12345678901234567890123456789012')})
        nonce, payload, signature = a.send(b'client1', b'123456')
        assert b.receive(b'server1', nonce, signature, payload)


        a = message.JsonAuthApi(b'server1',
                            {b'client1': ('12345678901234567890123456789012',
                                        '12345678901234567890123456789012')})

        b = message.JsonAuthApi(b'client1',
                            {b'server1': ('12345678901234567890123456789012',
                                        '12345678901234567890123456789012')})

        package = a.send(b'client1', {'this':'123456'})
        assert  b.receive(b'server1', package)


        a = message.JsonAuthApi(b'server1',
                            {b'client1': ('12345678901234567890123456789012',
                                        '12345678901234567890123456789012')},
                            cipher_cls=aes.Aes)
        b = message.JsonAuthApi(b'client1',
                            {b'server1': ('12345678901234567890123456789012',
                                        '12345678901234567890123456789012')},
                            cipher_cls=aes.Aes)
        package = a.send(b'client1', {'this':'123456'})
        assert  b.receive(b'server1', package) == {'this':'123456'}