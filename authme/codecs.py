import base64
import functools
import collections
import json as _json


def encode_all(data):
    if isinstance(data, bytes):
        return data
    elif isinstance(data, str):
        return data.encode()
    elif isinstance(data, collections.Mapping):
        return dict(map(encode_all, data.items()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(encode_all, data))
    else:
        return data


def decode_all(data):
    if isinstance(data, bytes):
        return data.decode()
    elif isinstance(data, collections.Mapping):
        return dict(map(decode_all, data.items()))
    elif isinstance(data, collections.Iterable):
        return type(data)(map(decode_all, data))
    else:
        return data


def b64encode(value):
    """
    """
    if isinstance(value, dict):
        return {b64encode(k): b64encode(v) for k, v in value.items()}
    elif isinstance(value, (tuple, list, set)):
        return type(value)([b64encode(v) for v in value])
    elif isinstance(value, (int, float)):
        return value
    else:
        assert isinstance(value, bytes), "Codec requires bytes value."
        return base64.b64encode(value)


def b64decode(value):
    """
    """
    if isinstance(value, dict):
        return {b64decode(k): b64decode(v) for k, v in value.items()}
    elif isinstance(value, (tuple, list, set)):
        return type(value)([b64decode(v) for v in value])
    else:
        assert isinstance(value, bytes), "Codec requires bytes value."
        return base64.b64decode(value)


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

class BaseArgCodec:
    """
    """
    @classmethod
    def encode(cls, *args):
        """
        """
        return tuple(cls._encode(*args))

    @classmethod
    def decode(cls, *args):
        """
        """
        return tuple(cls._decode(*args))

    @classmethod
    def _encode(cls, *args):
        """
        """
        for arg in args:
            yield arg

    @classmethod
    def _decode(cls, *args):
        """
        """
        for arg in args:
            yield arg


class B64ArgCodec(BaseArgCodec):
    """A message that is base64 encoded before delivery.
    This provides interoperability with platforms that cannot work with
    binary data.
    """
    @classmethod
    def _encode(cls, *args):
        for arg in BaseArgCodec._encode(*args):
            yield b64encode(arg)

    @classmethod
    def _decode(cls, *args):
        for arg in BaseArgCodec._decode(*args):
            yield b64decode(arg)


class JsonArgCodec(B64ArgCodec):
    """A message that is base64 encoded, then json encoded before encrypting.
    This provides interoperability with platforms that are troublesome
    when working with binary data. (i.e. Javascript)
    """
    @classmethod
    def _encode(cls, *args):
        for arg in B64ArgCodec._encode(*args):
            yield json.dumps(decode_all(arg))

    @classmethod
    def _decode(cls, *args):
        for arg in args:
            if isinstance(arg, bytes):
                arg = arg.decode()
            arg = json.loads(arg)
            yield from B64ArgCodec._decode(encode_all(arg))