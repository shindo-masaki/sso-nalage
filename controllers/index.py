from flask import render_template, Blueprint


app = Blueprint('index', __name__)


@app.route('/')
def index():
    return render_template('saml_signin.html')