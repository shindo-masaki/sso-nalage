import os
from flask import Flask
from crsf import setCSRF


app = Flask(__name__, instance_relative_config=True)
setCSRF(app)

from controllers import index, saml_auth, saml_signin, error_404


app.config.from_object('instance.config.Config')
app.config['SECRET_KEY'] = os.urandom(24)

app.register_blueprint(index)
app.register_blueprint(saml_auth)
app.register_blueprint(saml_signin)
app.register_blueprint(error_404)


if __name__ == '__main__':
    app.debug = True
    app.run(host='localhost', port=5000)