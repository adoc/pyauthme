import types

import unittest

import authme.codecs


class TestModule(unittest.TestCase):
    def test_encode_all(self):
        self.assertEqual(authme.codecs.encode_all('foo'), b'foo')

        self.assertEqual(authme.codecs.encode_all(('foo', 'bar', 'baz')),
                                                    (b'foo', b'bar', b'baz'))

        self.assertEqual(authme.codecs.encode_all({'foo', 'bar', 'baz'}),
                                                    {b'foo', b'bar', b'baz'})

        self.assertEqual(
            authme.codecs.encode_all({'foo': True, 'bar': 2, 'baz':'boo'}),
            {b'foo': True, b'bar': 2, b'baz': b'boo'})

    def test_decode_all(self):
        self.assertEqual(authme.codecs.decode_all(b'foo'), 'foo')

        self.assertEqual(authme.codecs.decode_all((b'foo', b'bar', b'baz')),
                                                    ('foo', 'bar', 'baz'))

        self.assertEqual(authme.codecs.decode_all({b'foo', b'bar', b'baz'}),
                                                    {'foo', 'bar', 'baz'})

        self.assertEqual(
            authme.codecs.decode_all({b'foo': True, b'bar': 2, b'baz': b'boo'}),
            {'foo': True, 'bar': 2, 'baz':'boo'})


class TestBaseArgCodec(unittest.TestCase):
    """
    """
    def test__encode(self):
        """
        """
        gen = authme.codecs.BaseArgCodec._encode(*range(10))
        self.assertIsInstance(gen, types.GeneratorType)
        self.assertEqual(tuple(gen), tuple(range(10)))

    def test__decode(self):
        """
        """
        gen = authme.codecs.BaseArgCodec._decode(*range(10))
        self.assertIsInstance(gen, types.GeneratorType)
        self.assertEqual(tuple(gen), tuple(range(10)))

    def test_encode(self):
        """
        """
        encoded = authme.codecs.BaseArgCodec.encode(*range(10))
        self.assertIsInstance(encoded, tuple)
        self.assertEqual(encoded, tuple(range(10)))

    def test_decode(self):
        """
        """
        decoded = authme.codecs.BaseArgCodec.decode(*range(10))
        self.assertIsInstance(decoded, tuple)
        self.assertEqual(decoded, tuple(range(10)))


class TestB64ArgCodec(unittest.TestCase):
    """
    """
    def test__encode(self):
        gen = authme.codecs.B64ArgCodec._encode(b'123', b'456', b'789')
        self.assertIsInstance(gen, types.GeneratorType)
        self.assertEqual(tuple(gen), (b'MTIz', b'NDU2', b'Nzg5'))

        gen = authme.codecs.B64ArgCodec._encode({b'foo': b'bar'})
        self.assertEqual(tuple(gen), ({b'Zm9v': b'YmFy'},))

    def test__decode(self):
        gen = authme.codecs.B64ArgCodec._decode(b'MTIz', b'NDU2', b'Nzg5')
        self.assertIsInstance(gen, types.GeneratorType)
        self.assertEqual(tuple(gen), (b'123', b'456', b'789'))

        gen = authme.codecs.B64ArgCodec._decode({b'Zm9v': b'YmFy'})
        self.assertEqual(tuple(gen), ({b'foo': b'bar'}, ))

    def test_encode(self):
        encoded = authme.codecs.B64ArgCodec.encode(b'123', b'456', b'789')
        self.assertIsInstance(encoded, tuple)
        self.assertEqual(encoded, (b'MTIz', b'NDU2', b'Nzg5'))

    def test_decode(self):
        decoded = authme.codecs.B64ArgCodec.decode(b'MTIz', b'NDU2', b'Nzg5')
        self.assertIsInstance(decoded, tuple)
        self.assertEqual(decoded, (b'123', b'456', b'789'))


class TestJsonArgCodec(unittest.TestCase):
    """
    """
    def test__encode(self):
        gen = authme.codecs.JsonArgCodec._encode(b'123', b'456', b'789')
        self.assertIsInstance(gen, types.GeneratorType)
        self.assertEqual(tuple(gen), ('"MTIz"', '"NDU2"', '"Nzg5"'))

        gen = authme.codecs.JsonArgCodec._encode({b'foo': b'bar'})
        self.assertEqual(tuple(gen), ('{"Zm9v":"YmFy"}',))

    def test__decode(self):
        gen = authme.codecs.JsonArgCodec._decode('{"Zm9v":"YmFy"}')
        self.assertIsInstance(gen, types.GeneratorType)
        self.assertEqual(tuple(gen), ({b'foo': b'bar'},))

        gen = authme.codecs.JsonArgCodec._decode('"MTIz"', '"NDU2"', '"Nzg5"')
        self.assertEqual(tuple(gen), (b'123', b'456', b'789'))