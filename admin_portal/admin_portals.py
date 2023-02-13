from flask import Blueprint, render_template, redirect, session, url_for, request, flash
from functools import wraps
from datetime import datetime
from flask_mysqldb import MySQL

import bcrypt

admin_stuff = Blueprint('admin_portal_main', __name__)

mysql = MySQL()


# BLOCK ADMIN ROUTES
def is_admin_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return f(*args, *kwargs)
        else:
            return redirect(url_for('admin_login'))
            # return '404 Page Not Found'

    return wrap


def not_admin_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return redirect(url_for('alan_code'))
        else:
            return f(*args, *kwargs)

    return wrap


@admin_stuff.route('/admin-login/', methods=['POST', 'GET'])
def admin_login():
    if request.method == 'POST':
        phone_no = request.form['phone_no']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM habahaba_trial.admin WHERE phone_no=%s", [phone_no])

        if result > 0:
            data = cur.fetchone()
            password = data['password']
            email = data['email']
            uid = data['admin_id']
            f_name = data['f_name']
            l_name = data['l_name']
            phone_no = data['phone_no']

            if bcrypt.checkpw(password_candidate.encode('utf-8'), password.encode('utf-8')):
                session['admin_logged_in'] = True
                session['admin_id'] = uid
                session['email'] = email
                session['f_name'] = f_name
                session['l_name'] = l_name
                session['phone_no'] = phone_no

                x = '1'

                cur.execute("UPDATE habahaba_trial.admin SET online=%s WHERE admin_id=%s", (x, uid))

                success = 'Login success'
                login_time = datetime.utcnow()
                action_performed = f'{f_name} {l_name} logged in'

                cur.execute(f"""
                INSERT INTO habahaba_trial.audit_report (admin_id, action_performed, action_time, success)
                VALUES (%s, %s, %s, %s)
                """, (
                    uid, action_performed, login_time, success
                ))
                mysql.connection.commit()

                return redirect(url_for('alan_code'))
            else:
                flash('Incorrect Password, please try again', 'danger')
                return redirect(url_for('admin_login'))
        else:
            flash('This phone number is not registered, please try again', 'danger')
            cur.close()
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')


@admin_stuff.route('/update-password/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_change_password():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.admin WHERE phone_no ='{session['phone_no']}' ")
    admin = cur.fetchone()

    pin = admin['password']
    cur.close()

    if request.method == 'POST':
        current_pin = request.form['current_pin']
        new_pin = request.form['new_pin']
        confirm_pin = request.form['confirm_pin']

        if current_pin or new_pin != int:
            flash("Your pin should only contain numbers", "danger")
            return redirect(url_for('admin_change_password'))

        if bcrypt.checkpw(current_pin.encode('utf-8'), pin.encode('utf-8')):
            if confirm_pin == new_pin:
                new_pin_value = bcrypt.hashpw(new_pin.encode('utf_8'), bcrypt.gensalt())

                cur = mysql.connection.cursor()
                cur.execute(f"""
                UPDATE habahaba_trial.admin
                SET password=%s
                WHERE phone_no=%s
                """, (
                    new_pin_value, admin['phone_no']
                ))
                mysql.connection.commit()
                cur.close()
                flash('Pin updated successfully', 'success')
                return redirect(url_for('admin_change_password'))
            else:
                flash('Your new pin and confirm pin must match!', 'danger')
                return redirect(url_for('admin_change_password'))
        else:
            flash('Wrong pin, please try again', 'danger')
            return redirect(url_for('admin_change_password'))
    return render_template('admin-change-password.html')


# admin logout
@admin_stuff.route('/admin-logout/', methods=['POST', 'GET'])
def admin_logout():
    # logout_user()
    if 'admin_id' in session:
        cur = mysql.connection.cursor()
        uid = session['admin_id']
        f_name = session['f_name']
        l_name = session['l_name']
        x = '0'
        cur.execute("UPDATE habahaba_trial.admin SET online=%s WHERE admin_id=%s ", (x, uid))

        success = 'Logged out successfully'
        logout_time = datetime.utcnow()
        action_performed = f'{f_name} {l_name} logged out'

        cur.execute(f"""
        INSERT INTO habahaba_trial.audit_report (admin_id, action_performed, action_time, success) 
        VALUES (%s, %s, %s, %s)
                        """, (
            uid, action_performed, logout_time, success
        ))
        mysql.connection.commit()

        session.clear()
        cur.close()
        flash(f'You are now logged out {f_name}', 'danger')
        return redirect(url_for('admin_login'))
    return redirect(url_for('admin_login'))


# admin home page
@admin_stuff.route('/admin-home/', methods=['POST', 'GET'])
@is_admin_logged_in
def alan_code():
    authorization_header = request.headers.get('Authorization')

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.users")
    users = cur.fetchall()
    cur.close()

    # all vendors
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.vendors")
    vendors = cur.fetchall()
    cur.close()

    # all products
    cur = mysql.connection.cursor()
    cur.execute("SELECT distinct crop_name FROM habahaba_trial.materials WHERE material_status = 'accepted'")
    products = cur.fetchall()
    cur.close()

    # all offers
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.offers")
    offers = cur.fetchall()
    cur.close()

    # transactions
    # vendor - user transactions
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.payments_table")
    payments = cur.fetchall()
    cur.close()

    # transactions
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.payment_transactions")
    transactions = cur.fetchall()
    cur.close()
    return render_template('alan_code.html', users=users, vendors=vendors, products=products,
                           offers=offers, payments=payments, transactions=transactions,

                           )
