from functools import wraps
from flask import g, redirect, url_for


class Auth():

    @classmethod
    def login_required(self, f):
        @wraps(f)
        def decorated_view(*args, **kwargs):
            if g.user is None:
                return redirect(url_for('index.index'))
            return f(*args, **kwargs)

        return decorated_view
