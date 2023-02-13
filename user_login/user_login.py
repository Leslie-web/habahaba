from flask import Blueprint, render_template

farmer_login = Blueprint('farmer_login', __name__)


@farmer_login.route('/l')
def farmers_login():
    return render_template('user_login.html')
