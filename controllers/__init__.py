from .index import app as index
from .saml_signin import app as saml_signin
from .api.v1.saml_auth import app as saml_auth
from .errors.error_404 import app as error_404


__all__ = [
    index,
    saml_auth,
    saml_signin,
    error_404
]