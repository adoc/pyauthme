"""Various exceptions thrown by this libarary."""



class SignatureException(Exception):
    pass


class SignatureBad(SignatureException):
    pass
    

class SignatureTimeout(SignatureException):
    pass



class AuthMessageException(Exception):
    """Base message authentication exception.
    """
    pass


class MessageClientBad(AuthMessageException):
    """Client wasn't found in the data model.
    """
    pass
