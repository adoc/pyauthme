""" """
import unittest

import cryptu.aes
import authme.hmac
import authme.message


class TestMessage(unittest.TestCase):
    """ """

    def test_default_message(self):
        """Test default passthrough behavior.
        """
        message = authme.message.Message(payload=b'payload')
        self.assertEqual(message.send(), (b'payload', None, None))

        message = authme.message.Message(payload=b'payload',
                                    signing_params=(b'signature_namespace',))
        self.assertEqual(message.send(), (b'payload', None, None))

        message = authme.message.Message()

        self.assertEqual(message.receive(b'payload', None, None), b'payload')
        self.assertEqual(message.receive(b'payload', b'challenge', b'signature_namespace'), b'payload')

    
    def test_message_signer(self):
        """
        """
        message = authme.message.Message(payload=b'payload',
                                         signer=authme.hmac.Hmac(b'12345'))
        self.assertEqual(message.send(),
                         (b'payload', None, b"""^\x10\x7f`'^V\r\xc0\x14:oe\xce\x98\xf2v{\t)\x8e<X\x0e\xaf\x99D\xc5\xca\x16\x16\xf9"""))

        message = authme.message.Message(payload=b'payload',
                                         signer=authme.hmac.Hmac(b'12345'),
                                         signing_params=(b'signature_namespace',))
        self.assertEqual(message.send(),
                         (b'payload', None, b"""K\xaa=\xcd\xde6\xd7\x07?1\xdd\x8a\xcb~\xf7"\x8c\xfe\x03R\xd7$\xf4b\x81Y\xb8\xfd\xcdD\xd6s"""))

        message = authme.message.Message(signer=authme.hmac.Hmac(b'12345'))
        self.assertEqual(message.receive(b'payload', None, b"""^\x10\x7f`'^V\r\xc0\x14:oe\xce\x98\xf2v{\t)\x8e<X\x0e\xaf\x99D\xc5\xca\x16\x16\xf9"""),
                         b'payload')

        message = authme.message.Message(signer=authme.hmac.Hmac(b'12345'),
                                         signing_params=(b'signature_namespace',))
        self.assertEqual(message.receive(b'payload', None, b"""K\xaa=\xcd\xde6\xd7\x07?1\xdd\x8a\xcb~\xf7"\x8c\xfe\x03R\xd7$\xf4b\x81Y\xb8\xfd\xcdD\xd6s"""),
                         b'payload')

    def test_message_cipher(self):
        key_iv = (b'\x1d\xc0s\xca\xc6\xf1\x18\x9a\xcb\x8bp\xec\x8d\xd7\xf1\x114\xcf\\\xa7I+\xc5#\x1c\xab\xbeC\xb5\xae\xecP', b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es')
        message = authme.message.Message(payload=b'payload',
                                         cipher=cryptu.aes.Aes(*key_iv))

        self.assertEqual(message.send(), (b"""?\x99\xdf\xc8\x98\xd4\x1b\xe7\x9cM\xce\xde\x9b\x12\x8d\xd7""", b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es', None))

        message = authme.message.Message(payload=b'payload',
                                         signing_params=(b'signature_namespace',),
                                         cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.send(), (b"""?\x99\xdf\xc8\x98\xd4\x1b\xe7\x9cM\xce\xde\x9b\x12\x8d\xd7""", b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es', None))

        message = authme.message.Message(cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.receive(b"""?\x99\xdf\xc8\x98\xd4\x1b\xe7\x9cM\xce\xde\x9b\x12\x8d\xd7""", b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es', None),
                         b'payload')

        message = authme.message.Message(signing_params=(b'signature_namespace',),
                                         cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.receive(b"""?\x99\xdf\xc8\x98\xd4\x1b\xe7\x9cM\xce\xde\x9b\x12\x8d\xd7""", b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es', None),
                         b'payload')

    def test_message_signer_cipher(self):
        key_iv = (b'\x1d\xc0s\xca\xc6\xf1\x18\x9a\xcb\x8bp\xec\x8d\xd7\xf1\x114\xcf\\\xa7I+\xc5#\x1c\xab\xbeC\xb5\xae\xecP', b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es')
        message = authme.message.Message(
                                    payload=b'payload',
                                    signer=authme.hmac.Hmac(b'12345'),
                                    cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.send(),
                         (b"""?\x99\xdf\xc8\x98\xd4\x1b\xe7\x9cM\xce\xde\x9b\x12\x8d\xd7""",
                          b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                          b"""\x00\x9e\xfe\xf2w\xbc\x8a\x14\xba\xc3\x88\x14C-\x12\x18\x00z\xbf"6\xe2\x1f\xc7Y\xa1\x86\xe7 8S\xb4"""))

        message = authme.message.Message(
                                    payload=b'payload',
                                    signer=authme.hmac.Hmac(b'12345'),
                                    signing_params=(b'signature_namespace',),
                                    cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.send(),
                         (b"""?\x99\xdf\xc8\x98\xd4\x1b\xe7\x9cM\xce\xde\x9b\x12\x8d\xd7""",
                          b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                          b"""\x81\x1dkjSfq\\ &2\xe3<\xc0Z\xcb\xa1\xa1\xc4)HK\xbf\t%\xefx\t\x8bXv\x07"""))

        message = authme.message.Message(
                                    signer=authme.hmac.Hmac(b'12345'),
                                    cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.receive(b"""?\x99\xdf\xc8\x98\xd4\x1b\xe7\x9cM\xce\xde\x9b\x12\x8d\xd7""",
                                         b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                                         b"""\x00\x9e\xfe\xf2w\xbc\x8a\x14\xba\xc3\x88\x14C-\x12\x18\x00z\xbf"6\xe2\x1f\xc7Y\xa1\x86\xe7 8S\xb4"""),
                         b'payload')

        message = authme.message.Message(
                            signer=authme.hmac.Hmac(b'12345'),
                            signing_params=(b'signature_namespace',),
                            cipher=cryptu.aes.Aes(*key_iv))

        self.assertEqual(message.receive(
                            b"""?\x99\xdf\xc8\x98\xd4\x1b\xe7\x9cM\xce\xde\x9b\x12\x8d\xd7""",
                            b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                            b"""\x81\x1dkjSfq\\ &2\xe3<\xc0Z\xcb\xa1\xa1\xc4)HK\xbf\t%\xefx\t\x8bXv\x07"""),
                         b'payload')


class TestJsonMessage(unittest.TestCase):
    """ """
    def test_default_message(self):
        """Test default passthrough behavior.
        """
        message = authme.message.JsonMessage(payload=1)
        self.assertEqual(message.send(), (b'1', None, None))

        message = authme.message.JsonMessage(payload=b"foobers")
        self.assertEqual(message.send(), (b'"Zm9vYmVycw=="', None, None))

        message = authme.message.JsonMessage(payload={b'foo': b'bar'})
        self.assertEqual(message.send(), (b'{"Zm9v":"YmFy"}', None, None))

        message = authme.message.JsonMessage(payload={b'foo': b'bar'},
                            signing_params=(b'signature_namespace',))
        self.assertEqual(message.send(), (b'{"Zm9v":"YmFy"}', None, None))


        message = authme.message.JsonMessage()
        self.assertEqual(message.receive('{"Zm9v":"YmFy"}', None, None), {b'foo': b'bar'})


        message = authme.message.JsonMessage(
                                    signing_params=(b'signature_namespace',))
        self.assertEqual(message.receive('{"Zm9v":"YmFy"}', None, None),
                                         {b'foo': b'bar'})

    def test_message_signer(self):
        """
        """
        message = authme.message.JsonMessage(payload=1,
                                             signer=authme.hmac.Hmac(b'12345'))
        self.assertEqual(message.send(), (b'1', None,  b'\x83g\xe8.y\xff3\x1b\xa3\r\x0f\x82D\xabC\x8bun\x8c\xef\xe5\xd5,\xe8,\x88a}\xc3{Z\xfc'))

        message = authme.message.JsonMessage(payload=b"foobers",
                                         signer=authme.hmac.Hmac(b'12345'))
        self.assertEqual(message.send(), (b'"Zm9vYmVycw=="', None, b'\x86\xc9\xaaQ\xc6\xd2\x14\xb0pO\x86\x13\xfe\xa6B\xfb\x11\x98U?Zi\x7f\xc2\t\xc5\xf7\x03m?]\xbc'))

        message = authme.message.JsonMessage(payload={b'foo': b'bar'},
                                         signer=authme.hmac.Hmac(b'12345'))
        self.assertEqual(message.send(),
            (b'{"Zm9v":"YmFy"}', None, b'\x7f\x80o(\x8b,\xa6|\xb4w\x80o\xcb\xa2\xf0:\xd7\xf8\x8b\xee"3o\xbe\x17~{TAj\xbe\xf9'))


        message = authme.message.JsonMessage(payload={b'foo': b'bar'},
                                         signer=authme.hmac.Hmac(b'12345'))
        self.assertEqual(message.send(),
            (b'{"Zm9v":"YmFy"}', None, b'\x7f\x80o(\x8b,\xa6|\xb4w\x80o\xcb\xa2\xf0:\xd7\xf8\x8b\xee"3o\xbe\x17~{TAj\xbe\xf9'))

        message = authme.message.JsonMessage(payload={b'foo': b'bar'},
                                         signer=authme.hmac.Hmac(b'12345'),
                                         signing_params=(b'signature_namespace',))
        self.assertEqual(message.send(),
            (b'{"Zm9v":"YmFy"}', None, b'\x12r%\xa5O\xad\xfc\xad\x91\x11\xd6x5\xc3\xa3\xaci\xedR{\xf7\xbfK\n\x7fe\x14\xbd\xd3\xcf\xc3\xe2'))


        message = authme.message.JsonMessage(signer=authme.hmac.Hmac(b'12345'))
        self.assertEqual(message.receive(b'{"Zm9v":"YmFy"}', None, b'\x7f\x80o(\x8b,\xa6|\xb4w\x80o\xcb\xa2\xf0:\xd7\xf8\x8b\xee"3o\xbe\x17~{TAj\xbe\xf9'),
                         {b'foo': b'bar'})

        message = authme.message.JsonMessage(signer=authme.hmac.Hmac(b'12345'),
                                         signing_params=(b'signature_namespace',))
        self.assertEqual(
            message.receive(b'{"Zm9v":"YmFy"}', None, b'\x12r%\xa5O\xad\xfc\xad\x91\x11\xd6x5\xc3\xa3\xaci\xedR{\xf7\xbfK\n\x7fe\x14\xbd\xd3\xcf\xc3\xe2'),
                         {b'foo': b'bar'})

    def test_message_cipher(self):
        key_iv = (b'\x1d\xc0s\xca\xc6\xf1\x18\x9a\xcb\x8bp\xec\x8d\xd7\xf1\x114\xcf\\\xa7I+\xc5#\x1c\xab\xbeC\xb5\xae\xecP', b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es')

        message = authme.message.JsonMessage(payload=1,
                                         cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.send(), (b'#\x89\xa6\xbfr\xe5\xbd\xe7\xa4D\xfe!\xfet\x89\x97', b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es', None))

        message = authme.message.JsonMessage(payload=b"foobers",
                                         cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.send(), (b"\x1eI'c\x89\n\xf0\xc5+\xed\xff\xcbP\xc6!W", b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es', None))

        message = authme.message.JsonMessage(payload={b'foo': b'bar'},
                                         cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.send(),
                            (b'\x93O\x85\x1acG\x83X\x8b0CO\x07\xaa\x8aO',
                            b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                            None))

        message = authme.message.JsonMessage(payload={b'foo': b'bar'},
                                         signing_params=(b'signature_namespace',),
                                         cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.send(),
                            (b'\x93O\x85\x1acG\x83X\x8b0CO\x07\xaa\x8aO',
                            b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                            None))

        message = authme.message.JsonMessage(cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.receive(
                            b'\x93O\x85\x1acG\x83X\x8b0CO\x07\xaa\x8aO',
                            b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                            None),
                         {b'foo': b'bar'})

        message = authme.message.JsonMessage(signing_params=(b'signature_namespace',),
                                         cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.receive(
                            b'\x93O\x85\x1acG\x83X\x8b0CO\x07\xaa\x8aO',
                            b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                            None),
                         {b'foo': b'bar'})

    def test_message_signer_cipher(self):
        key_iv = (b'\x1d\xc0s\xca\xc6\xf1\x18\x9a\xcb\x8bp\xec\x8d\xd7\xf1\x114\xcf\\\xa7I+\xc5#\x1c\xab\xbeC\xb5\xae\xecP', b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es')

        message = authme.message.JsonMessage(
                                    payload=1,
                                    signer=authme.hmac.Hmac(b'12345'),
                                    cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.send(), (
                                b'#\x89\xa6\xbfr\xe5\xbd\xe7\xa4D\xfe!\xfet\x89\x97',
                                b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                                b'\x01\xae{\x0c=\xc5\x18\x0eq\r)n\xe48\xafj\x0b\txRB\x1a\x90[\xeb\x9b\x17x\xaa\x8e\x9fF'))

        message = authme.message.JsonMessage(
                                    payload=b'payload',
                                    signer=authme.hmac.Hmac(b'12345'),
                                    cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.send(),
                         (b'\xc3r\xb9\x8ce\xd4\xe8Fv\xe3\xfa\xd3\xc7\xbb\x05C',
                          b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                          b'k\xd5\xcf\xb1-F\xf2#\x07\xa9S\x0f\xc6\x9f\x86\r=VY\x07\x9f\x1d\x83\xb2D\xe2B}\x1a$\xdck'))

        message = authme.message.JsonMessage(
                                    payload=b'payload',
                                    signer=authme.hmac.Hmac(b'12345'),
                                    signing_params=(b'signature_namespace',),
                                    cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.send(),
                         (b'\xc3r\xb9\x8ce\xd4\xe8Fv\xe3\xfa\xd3\xc7\xbb\x05C',
                          b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                          b'\xb1\xcbs\xe9\x04\x00\x1c\x8d&Yh\xd8\xd5\\\xc6\x1c\x06\xc3\xe0w\xe3\x03\xc0-\xa2&\xa9\xe1\xc1j\xfa\xb2'))

        message = authme.message.JsonMessage(
                                    signer=authme.hmac.Hmac(b'12345'),
                                    cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.receive(b'\xc3r\xb9\x8ce\xd4\xe8Fv\xe3\xfa\xd3\xc7\xbb\x05C',
                                         b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                                         b'k\xd5\xcf\xb1-F\xf2#\x07\xa9S\x0f\xc6\x9f\x86\r=VY\x07\x9f\x1d\x83\xb2D\xe2B}\x1a$\xdck'),
                        b'payload')

        message = authme.message.JsonMessage(
                            signer=authme.hmac.Hmac(b'12345'),
                            signing_params=(b'signature_namespace',),
                            cipher=cryptu.aes.Aes(*key_iv))
        self.assertEqual(message.receive(
                            b'\xc3r\xb9\x8ce\xd4\xe8Fv\xe3\xfa\xd3\xc7\xbb\x05C',
                            b'"\x87{*\xadl\xe5\xd7d\xf8j\xfd\xd4\xd7\x1es',
                            b'\xb1\xcbs\xe9\x04\x00\x1c\x8d&Yh\xd8\xd5\\\xc6\x1c\x06\xc3\xe0w\xe3\x03\xc0-\xa2&\xa9\xe1\xc1j\xfa\xb2'),
                        b'payload')




    '''
    def test_temporary_message(self):



        # Not a real test, just some dev code.

        a = authme.message.Message(signer=authme.hmac.TimedHmac(b'12345',
                                   expiry=1),
                                cipher=cryptu.aes.Aes(
                                            *cryptu.aes.gen_keyiv()))

        msg = b'a'
        payload, sig = a.send(msg)
        assert a.receive(payload, sig)
    '''
    '''
    def test_temporary_auth_api(self):
        # Not a real test, just some dev code.

        a = authme.message.AuthApi(b'server1',
                            {b'client1': {'secret':
                                            b'12345678901234567890123456789012',
                                        'key': b''}})

        b = authme.message.AuthApi(b'client1',
                            {b'server1': {'secret':
                                            b'12345678901234567890123456789012',
                                        'key': b''}})
        nonce, payload, signature = a.send(b'client1', b'123456')
        assert b.receive(b'server1', nonce, signature, payload)

        nonce, payload, signature = a.send(b'client1', {'foo':'123456'})


        a = authme.message.JsonAuthApi(b'server1',
                            {b'client1': {'secret':
                                            b'12345678901234567890123456789012',
                                        'key': b''}})

        b = authme.message.JsonAuthApi(b'client1',
                            {b'server1': {'secret':
                                            b'12345678901234567890123456789012',
                                        'key': b''}})

        package = a.send(b'client1', {'this':'123456'})
        assert  b.receive(package)

        a = authme.message.JsonAuthApi(b'server1',
                            {b'client1': {'secret':
                                            b'12345678901234567890123456789012',
                                        'key': b''}},
                            cipher_cls=cryptu.aes.Aes)
        b = authme.message.JsonAuthApi(b'client1',
                            {b'server1': {'secret':
                                            b'12345678901234567890123456789012',
                                        'key': b''}},
                            cipher_cls=cryptu.aes.Aes)
        package = a.send(b'client1', {'this':'123456'})

        assert  b.receive(package) == {'this':'123456'}'''