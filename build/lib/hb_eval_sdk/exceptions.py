"""
HB-Eval SDK — exception hierarchy.

All SDK exceptions inherit from HBEvalError, so a caller can catch the base
class to handle any SDK-originated failure. ValidationError is new in v2.1.0:
it lets the SDK refuse a malformed payload locally, before any encryption or
network call, which is the client half of the defense-in-depth in Protocol §5.
"""


class HBEvalError(Exception):
    """Base exception for all HB-Eval SDK errors."""
    pass


class ValidationError(HBEvalError):
    """Raised when a payload fails local validation before being sent."""
    pass


class ConnectionError(HBEvalError):
    """Raised when the connection to the Gateway fails."""
    pass


class AuthenticationError(HBEvalError):
    """Raised when the API key or signature is rejected by the Gateway."""
    pass


class EncryptionError(HBEvalError):
    """Raised when encryption or key handling fails."""
    pass


class SafeHaltError(HBEvalError):
    """
    Raised when the Safe Halt protocol activates — the client lost contact
    with the reliability core and must stop rather than proceed unevaluated.

    A reliability system fails closed: if it cannot verify, it does not
    pretend success. The reason field carries a machine-readable cause.
    """

    def __init__(self, message: str, reason: str = "CONNECTION_LOST_MANDATORY_HALT"):
        super().__init__(message)
        self.reason = reason
