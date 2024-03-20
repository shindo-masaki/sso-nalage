from flask import Blueprint, render_template


app = Blueprint('404', __name__)

@app.errorhandler(404)
def error_404(error):
    return render_template('error_pages/404.html'), 404