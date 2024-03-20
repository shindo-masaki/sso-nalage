from flask_wtf.csrf import CSRFProtect

csrf = None

def setCSRF(app):
    global csrf
    csrf = CSRFProtect(app)
    csrf.init_app(app)