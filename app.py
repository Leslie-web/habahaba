# for daraja api
import base64
import random

import MySQLdb
import requests
import json
import bcrypt
import jwt
import csv

from requests.auth import HTTPBasicAuth

from flask import *
from flask_mysqldb import MySQL

# from passlib.hash import sha256_crypt
from functools import wraps
from datetime import date, datetime, timedelta
# import datetime

from counties import counties
from machine_learning_model.machine_learning_main import ml
from user_login.user_login import farmer_login

# from admin_portal.admin_portals import admin_stuff

# ngrok
# from flask_ngrok import run_with_ngrok

app = Flask(__name__)
# run_with_ngrok(app)

app.register_blueprint(ml)
app.register_blueprint(farmer_login)
# app.register_blueprint(admin_stuff)

mysql = MySQL()
app.secret_key = 'erxycutvhkbjlnk'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'habahaba_trial'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

app.config['JWT_SECRET_KEY'] = 'qwerty'

# app.secret_key = 'erxycutvhkbjlnk'
# app.config['MYSQL_HOST'] = '13.231.240.156'
# app.config['MYSQL_USER'] = 'habahaba_usa'
# app.config['MYSQL_PASSWORD'] = 'h@b@h@b@#'
# app.config['MYSQL_DB'] = 'habahaba_trial'
# app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql.init_app(app)


# def token_required(f):
#     wraps(f)
#
#     def decorated(*args, **kwargs):
#         token = requests.get('token')
#         if not token:
#             return jsonify({'message': 'Token is missing'}), 403
#
#         try:
#             data = jwt.decode(token, app.config['JWT_SECRET_KEY'])
#         except:
#             return jsonify({'message': 'Token is invalid'}), 403
#
#         return decorated

@app.errorhandler(404)
def pages_not_found(e):
    return render_template('vendor_page_not_found.html'), 404


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('502_error_page.html'), 500


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


# BLOCK CLIENT DETAILS
def is_user_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('user_login'))

    return wrap


def not_user_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_logged_in' in session:
            return redirect(url_for('ukulima'))
        else:
            return f(*args, **kwargs)

    return wrap


# BLOCK VENDOR LOGIN
# super admin = 0
# regular admin = 1
def is_vendor_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'vendor_logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('vendor_login'))

    return wrap


def not_vendor_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'vendor_logged_in' in session:
            return redirect(url_for('vendor_login'))
        else:
            return f(*args, **kwargs)

    return wrap


def wrappers(func, *args, **kwargs):
    def wrapped():
        return func(*args, **kwargs)

    return wrapped


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[DATATABLES]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
def datatable(table_result):
    dataTable = []
    for row in table_result:
        row_list = []
        for item in row:
            row_list.append(row[item])
        dataTable.append(row_list)
    return jsonify({"data": dataTable})


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ADMIN ROUTES]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
# admin registration
@app.route('/admin-registration/', methods=['POST', 'GET'])
def admin_registration():
    password_pin = random.randint(1000, 9999)
    password = str(password_pin)
    registration_date = datetime.today()
    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        email = request.form['email']
        residence = request.form['residence']
        dob = request.form['dob']
        phone_no = request.form['phone_no']
        passwords = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # password = sha256_crypt.encrypt(str(request.form['password']))

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.admin (f_name, l_name, email, residence, dob, phone_no,"
                        " password, date_registered) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (
                            f_name, l_name, email, residence, dob, phone_no, passwords, registration_date
                        ))
            mysql.connection.commit()
            cur.close()

            admin_text_msg(phone_no, password)
            flash("Admin registered successfully", "green lighten-2")
            return redirect(url_for('admin_login'))

        except(MySQLdb.Error, MySQLdb.Warning) as e:
            flash('This email already exists, Please enter another one', 'red lighten-2')
            return redirect(url_for('admin_registration'))
    return render_template('admin_registration.html')


# admin login
@app.route('/admin-login/', methods=['POST', 'GET'])
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


@app.route('/update-password/', methods=['POST', 'GET'])
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
@app.route('/admin-logout/', methods=['POST', 'GET'])
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
@app.route('/admin-home/', methods=['POST', 'GET'])
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
    # cur = mysql.connection.cursor()
    # cur.execute("SELECT * FROM habahaba_trial.payments_table")
    # payments = cur.fetchall()
    # cur.close()

    # transactions
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.payment_transactions WHERE transaction_status=1")
    transactions = cur.fetchall()
    cur.close()
    return render_template('alan_code.html', users=users, vendors=vendors, products=products,
                           offers=offers, transactions=transactions
                           )


@app.route('/categories-report/', methods=['GET'])
def a_categories_reports():
    # cur = mysql.connection.cursor()
    # cur.execute("SELECT category FROM habahaba_trial.payments_table")
    # categories = cur.fetchall()
    # cur.close()
    return render_template('a_category_reports.html')


# VENDOR SETUP
@app.route('/vendor-setup/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_vendor_setup():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.vendors WHERE acc_status = 'pending'")
    org_name = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        # id_no = request.form['id_no']
        # phone_no = request.form['phone_no']
        gender = request.form.get('gender')
        payment_method = request.form.get('payment_method')
        acc_number = request.form['acc_number']
        org_location = request.form['org_location']
        commission = request.form['commission']
        organization_name = request.form['org_name']

        vendor_status = 'set_up'

        try:
            cur = mysql.connection.cursor()
            cur.execute(f"""
            UPDATE habahaba_trial.vendors
            SET f_name=%s, l_name=%s, gender=%s, payment_method=%s, acc_number=%s, location=%s,
             commission=%s, acc_status=%s
             WHERE org_name='{organization_name}' AND acc_status = 'pending'
            """, (
                f_name, l_name, gender, payment_method, acc_number, org_location, commission,
                vendor_status
            ))
            mysql.connection.commit()

            action_performed = f'{f_name} {l_name} set up {organization_name} successfully'
            action_time = datetime.utcnow()
            success = f'Setup Vendor success'

            cur.execute(f"""
            INSERT INTO habahaba_trial.audit_report (admin_id, action_performed, action_time, success) 
            VALUES (%s, %s, %s, %s)
                                            """, (
                session['admin_id'], action_performed, action_time, success
            ))
            mysql.connection.commit()
            cur.close()
            flash("Vendor has been set up successfully", "success")
            return redirect(url_for('admin_vendor_setup'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            action_performed = f'{f_name} {l_name} failed to set up Vendor'
            action_time = datetime.utcnow()
            success = f'Vendor Setup Failed'
            additional_info = f"{e}"

            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.audit_report (admin_id, action_performed, action_time, success, additional_details) 
            VALUES (%s, %s, %s, %s, %s)
                                                        """, (
                session['admin_id'], action_performed, action_time, success, additional_info
            ))
            mysql.connection.commit()
            cur.close()
            flash("Error setting up Vendor!", "warning")
            return redirect(url_for('admin_vendor_setup'))
        # except (MySQLdb.Error, MySQLdb.Warning) as e:
        #     print(e)
        #     flash('Duplicate entry entered, please try again', 'warning')
        #     return redirect(url_for('admin_vendor_setup'))
    return render_template('admin_vendor_setup.html', org_name=org_name)


@app.route('/create-user/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_create_user():
    # generate a 4 number pin
    password_pin = random.randint(1000, 9999)
    password = str(password_pin)
    date_registered = datetime.today()
    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        residence = request.form['residence']
        phone_no = request.form['phone_no']
        # password = sha256_crypt.encrypt(str(request.form['password']))
        passwords = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        account_type = request.form['account_type']

        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO habahaba_trial.admin (f_name, l_name, residence, phone_no, account_type, password,"
                " date_registered) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s)", (
                    f_name, l_name, residence, phone_no, account_type, passwords, date_registered
                ))
            mysql.connection.commit()
            cur.close()

            admin_text_msg(phone_no, password)
            flash('User added successfully', 'success')
            return redirect(url_for('admin_create_user'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            flash('This phone number already exists', 'danger')
            return redirect(url_for('admin_create_user'))
    return render_template('admin-create-users.html')


# Onboarding Vendors
@app.route('/vendor-onboarding/', methods=['POST', 'GET'])
@is_admin_logged_in
def vendor_onboarding():
    password_pin = random.randint(1000, 9999)
    password = str(password_pin)

    today = datetime.today()

    if request.method == 'POST':
        general_industry = request.form['general_industry']
        org_name = request.form['org_name']
        phone_no = request.form['phone_no']
        # password = sha256_crypt.encrypt(str(request.form['password']))
        passwords = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        acc_status = 'pending'
        acc_type = 0
        ac_type = 'Vendor'

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.vendors ( org_name, general_industry, acc_status, passwords,"
                        "account_type, phone_no, date_registered) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s)", (
                            org_name, general_industry, acc_status, passwords, acc_type, phone_no, today
                        ))
            mysql.connection.commit()
            cur.close()

            vendor_text_msg(phone_no, password)

            success = 'Onboarded a Vendor successfully'
            action_time = datetime.utcnow()
            action_performed = f"{session['f_name']} {session['l_name']} onboarded {general_industry}"

            cur = mysql.connection.cursor()
            cur.execute(f"""
                    INSERT INTO habahaba_trial.audit_report (admin_id, action_performed, action_time, success) 
                    VALUES (%s, %s, %s, %s)
                                    """, (
                session['admin_id'], action_performed, action_time, success
            ))
            mysql.connection.commit()
            cur.close()

            flash("Vendor added successfully. Please setup the vendor at Vendor Setup", "success")
            return redirect(url_for('vendor_onboarding'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            # print(MySQLdb.Error(e))
            success = f'{e}'
            action_time = datetime.utcnow()
            action_performed = f"{session['f_name']} {session['l_name']} failed to onboard a Vendor"

            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.audit_report (admin_id, action_performed, action_time, success) 
            VALUES (%s, %s, %s, %s)
                                                """, (
                session['admin_id'], action_performed, action_time, success
            ))
            mysql.connection.commit()
            cur.close()
            flash("This organization is already registered, please enter a different one", "danger")
            return redirect(url_for('vendor_onboarding'))
    return render_template('admin_onboard_vendors.html', today=today)


@app.route('/categories-columns/', methods=['GET'])
def categories_column():
    cur = mysql.connection.cursor()
    # cur.execute("DESCRIBE habahaba_trial.users")
    cur.execute("show columns from habahaba_trial.users")
    users = cur.fetchall()
    cur.close()
    # return datatable(users)
    return json.dumps(users)


# ADMIN TRANSACTIONS
@app.route('/transactions/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_transactions():
    if request.method == 'POST':
        client_id = request.form['client_id']
        cur = mysql.connection.cursor
        return redirect(url_for('admin_individual_transactions'))
    return render_template('admin_transactions.html')


# ADMIN HOMEPAGE
@app.route('/admin-homepage/', methods=['POST', 'GET'])
def admin_homepage():
    return render_template('admin_homepage.html')


# ADMIN PRODUCT VERIFICATION
# @app.route('/product-verification/', methods=['POST', 'GET'])
# @is_admin_logged_in
# def admin_product_verification():
#     cur = mysql.connection.cursor()
#     cur.execute("SELECT * FROM habahaba_trial.materials ORDER BY material_id DESC ")
#     vendor_products = cur.fetchall()
#     cur.close()
#
#     if request.method == 'POST':
#         ids = request.form['ids']
#         action_selected = request.form.get('action_selected')
#
#         cur = mysql.connection.cursor()
#     cur.execute("UPDATE habahaba_trial.materials SET material_status=%s WHERE material_id=%s",
#                 (action_selected, ids))
#     mysql.connection.commit()
#     cur.close()
#     flash('Action completed successfully', 'green lighten-2')
#     return redirect(url_for('admin_product_verification'))
# return render_template('admin_product_verification.html', vendor_products=vendor_products)


# ADMIN VIEW USERS
@app.route('/admin-view-users/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_view_users():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.users")
    users = cur.fetchall()
    cur.close()
    return render_template('adimn_view_users.html', users=users)


# ADMIN VENDOR REPORTS
@app.route('/vendor-reports/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_vendor_reports():
    return render_template('admin_vendor_report.html')


@app.route('/campaign-reports-json/', methods=['POST', 'GET'])
@is_admin_logged_in
def a_campaign_report_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT offer_id, offer_name, org_name, percentage_off FROM habahaba_trial.offers WHERE offer_status = 'accepted'")
    campaign = cur.fetchall()
    cur.close()
    return datatable(campaign)


@app.route('/payments-example/', methods=['GET'])
def payments_example():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT transaction_id, sender_name, org_name, amount_sent FROM habahaba_trial.payment_transactions
    """)
    payments = cur.fetchall()
    cur.close()
    return datatable(payments)


# CAMPAIGN REPORT
@app.route('/campaign-report/', methods=['GET'])
@is_admin_logged_in
def a_campaign_report():
    return render_template('a_campaign_report.html')


@app.route('/commission-report/', methods=['GET'])
@is_admin_logged_in
def a_commission_report():
    return render_template('a_commission_report.html')


@app.route('/commission-report-json/', methods=['GET'])
@is_admin_logged_in
def a_commission_report_report():
    cur = mysql.connection.cursor()
    cur.execute("SELECT max(vendor_name), max(vendor_name), max(category), sum(commission), "
                "max(date_paid) FROM habahaba_trial.commission GROUP BY vendor_name, category")
    commission = cur.fetchall()
    cur.close()
    return datatable(commission)


@app.route('/redemptions-summary/', methods=['GET'])
@is_admin_logged_in
def a_redemption_summary():
    return render_template('a_redemption_summary.html')


@app.route('/redemptions-summary-json/', methods=['GET'])
@is_admin_logged_in
def a_redemptions_summary_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT f_name, concat_ws(' ', f_name, l_name), vendor_org, category, amount_redeemed, DATE(date_redeemed), redemption_location
     FROM habahaba_trial.redemption 
     RIGHT JOIN habahaba_trial.users ON client_id = user_id WHERE amount_redeemed != 'null'
    """)
    redemptions_summary = cur.fetchall()
    cur.close()
    return datatable(redemptions_summary)


@app.route('/vendor-summary/', methods=['GET'])
@is_admin_logged_in
def a_vendor_summary():
    return render_template('a_vendor_summary.html')


@app.route('/audit-report-json/', methods=['GET'])
@is_admin_logged_in
def a_audit_report_json():
    cur = mysql.connection.cursor()
    cur.execute("""
    SELECT  audit_id, action_performed, action_performed, action_time, success, additional_details, admin_id, vendor_id, sender_id
     FROM habahaba_trial.audit_report
    """)
    audit = cur.fetchall()
    cur.close()
    return datatable(audit)


@app.route('/audit-report/', methods=['GET'])
@is_admin_logged_in
def a_audit_report():
    return render_template('a_audit_report.html')


@app.route('/balance-summary/', methods=['GET'])
@is_admin_logged_in
def a_balance_summary():
    return render_template('a_balance_summary.html')


@app.route('/balance-summary-json/', methods=['GET'])
def a_balance_summary_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM ")
    return


@app.route('/farm-scale/', methods=['GET'])
@is_admin_logged_in
def a_farm_scale():
    return render_template('a_farm_scale.html')


# @app.route('/farm-scale-test-json/', methods=['GET'])
# @is_admin_logged_in
# def a_farm_scale_test_json():
#     cur = mysql.connection.cursor()
#     cur.execute(f"""
#     SELECT max(concat_ws(' ', f_name, l_name)) as sender_name, max(saving_target / (partnership.quantity_per_acre * partnership.price_per_kg)),
#     max(crop_name) as crop_name, max(partnership_id) as partnership_id
#     FROM habahaba_trial.partnership
#     RIGHT JOIN habahaba_trial.users ON client_id=user_id
#     RIGHT JOIN habahaba_trial.materials ON item_id=material_id
#     GROUP BY crop_name
#     """)
#     item = cur.fetchall()
#     cur.close()
#     return json.dumps(item)


@app.route('/farm-scale-json/', methods=['GET'])
@is_admin_logged_in
def a_farm_scale_json():
    cur = mysql.connection.cursor()
    # cur.execute("""
    # SELECT sender_name, (saving_target / (quantity_per_acre * payments_table.price_per_kg)),
    #  payment_for, payment_id FROM habahaba_trial.payments_table
    # """)
    cur.execute(f"""
        SELECT max(concat_ws(' ', f_name, l_name)) as sender_name, max(saving_target / (partnership.quantity_per_acre * partnership.price_per_kg)),
        max(crop_name) as crop_name, max(partnership_id) as partnership_id 
        FROM habahaba_trial.partnership
        RIGHT JOIN habahaba_trial.users ON client_id=user_id
        RIGHT JOIN habahaba_trial.materials ON item_id=material_id WHERE partnership_id != 'null'
        GROUP BY crop_name
        """)
    farm_scale = cur.fetchall()
    cur.close()
    return datatable(farm_scale)


@app.route('/crop-summary/', methods=['GET'])
@is_admin_logged_in
def a_crop_summary():
    return render_template('a_crop_summary.html')


# @app.route('/crop-summary-test-json/', methods=['GET'])
# @is_admin_logged_in
# def a_crop_summary_test_json():
#     cur = mysql.connection.cursor()
#     cur.execute(f"""
#     SELECT max(concat_ws(' ', f_name, l_name)) as sender_name, max(crop_name) as payment_for,
#     max(format(saving_target / (partnership.quantity_per_acre * partnership.price_per_kg), 2)) as land_size,
#     max(vendor_org) as vendor_org, max(vendor_org) as vendor_org, max(partnership_id) as partnership_id
#     FROM habahaba_trial.partnership
#     RIGHT JOIN habahaba_trial.materials ON item_id=material_id
#     RIGHT JOIN habahaba_trial.users ON client_id=user_id
#     GROUP BY crop_name
#     """)
#     item = cur.fetchall()
#     cur.close()
#     return json.dumps(item)


@app.route('/crop-summary-json/', methods=['GET'])
@is_admin_logged_in
def a_crop_summary_json():
    cur = mysql.connection.cursor()
    # cur.execute("""
    # SELECT sender_name, payment_for,
    # format(saving_target / (quantity_per_acre * payments_table.price_per_kg), 2), org_name, org_name, payment_id
    # FROM habahaba_trial.payments_table
    # """)
    cur.execute(f"""
        SELECT max(concat_ws(' ', f_name, l_name)) as sender_name, max(crop_name) as payment_for,
        max(format(saving_target / (partnership.quantity_per_acre * partnership.price_per_kg), 2)) as land_size,
        max(vendor_org) as vendor_org, max(vendor_org) as vendor_org, max(partnership_id) as partnership_id
        FROM habahaba_trial.partnership
        RIGHT JOIN habahaba_trial.materials ON item_id=material_id 
        RIGHT JOIN habahaba_trial.users ON client_id=user_id
        GROUP BY crop_name, concat_ws(' ', f_name, l_name), 
        format(saving_target / (partnership.quantity_per_acre * partnership.price_per_kg), 2)
        """)
    crop_summary = cur.fetchall()
    cur.close()
    return datatable(crop_summary)


@app.route('/saving-summary/', methods=['GET'])
@is_admin_logged_in
def a_saving_summary():
    return render_template('a_saving_summary.html')


# @app.route('/saving-summary-test-json/', methods=['GET'])
# @is_admin_logged_in
# def a_saving_summary_test_json():
#     cur = mysql.connection.cursor()
#     cur.execute(f"""
#     SELECT max(transaction_id) as transaction_id, max(concat_ws(' ', f_name, l_name)) as sender_name,
#     sum(amount_saved_daily) as amount_saved_daily, max(category) as category
#     FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.users ON sender_id=user_id
#     """)
#     item = cur.fetchall()
#     cur.close()
#     return json.dumps(item)


@app.route('/saving-summary-json/', methods=['GET'])
@is_admin_logged_in
def a_saving_summary_json():
    cur = mysql.connection.cursor()
    # cur.execute("""
    # SELECT payment_id, sender_name, amount_sent, category FROM habahaba_trial.payments_table
    # """)
    cur.execute(f"""
        SELECT max(transaction_id) as transaction_id, max(concat_ws(' ', f_name, l_name)) as sender_name,
        sum(amount_saved_daily) as amount_saved_daily, max(category) as category  
        FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.users ON sender_id=user_id 
        WHERE transaction_status = 1
        GROUP BY sender_name
        """)
    saving_summary = cur.fetchall()
    cur.close()
    return datatable(saving_summary)


@app.route('/campaigns/', methods=['GET'])
@is_admin_logged_in
def a_campaign_summary():
    return render_template('a_campaign_summary.html')


@app.route('/campaigns-json/', methods=['GET'])
@is_admin_logged_in
def a_campaign_summary_json():
    cur = mysql.connection.cursor()
    cur.execute("""
    SELECT max(offers.campaign_name), max(offers.campaign_name), max(org_name), max(percentage_off), count(*), 
    max(item_name)
    FROM habahaba_trial.offers INNER JOIN habahaba_trial.picked_offer on offers.offer_id = picked_offer.offer_id  
    WHERE offer_status = 'Accepted' 
    GROUP BY picked_offer.campaign_name, item_name
    """)
    campaigns_summary = cur.fetchall()
    cur.close()
    return datatable(campaigns_summary)


@app.route('/vendor-insight/', methods=['GET'])
@is_admin_logged_in
def a_vendor_insight():
    return render_template('a_vendor_insight.html')


# @app.route('/vendor-insight-test-json/', methods=['GET'])
# def a_vendor_insight_test_json():
#     # (format((sum(saving_target) / (sum(price_per_kg) * sum(quantity_per_acre))), 2)) as calc2
#     cur = mysql.connection.cursor()
#     cur.execute(f"""
#     SELECT max(vendor_org) as org_name, max(category) as category, (count(category)) as calc1,
#     (sum(size_of_land)) as land_size
#      FROM habahaba_trial.partnership
#      RIGHT JOIN habahaba_trial.users ON client_id=user_id WHERE user_id=client_id GROUP BY category, client_id
#     """)
#     item = cur.fetchall()
#     cur.close()
#     return json.dumps(item)


@app.route('/vendor-insight-json/', methods=['GET'])
def a_vendor_insight_json():
    cur = mysql.connection.cursor()
    # format(((count(*) / avg(client_id)) * 100), 2)
    # cur.execute(f"""SELECT max(org_name), max(category), ((count(*) / avg(sender_id)) * 100),
    #     format((sum(saving_target) / (sum(price_per_kg) * sum(quantity_per_acre))), 2)
    #     FROM habahaba_trial.payments_table GROUP BY category, org_name""")
    cur.execute(f"""
        SELECT max(vendor_org) as org_name, max(category) as category, format(((count(category) / avg(client_id)) * 100), 2) as calc1,
        (sum(size_of_land)) as land_size
         FROM habahaba_trial.partnership 
         RIGHT JOIN habahaba_trial.users ON client_id=user_id WHERE user_id=client_id GROUP BY vendor_org 
    """)
    vendor_insight = cur.fetchall()
    cur.close()

    return datatable(vendor_insight)


@app.route('/vendor-summary-test-json/', methods=['GET'])
@is_admin_logged_in
def a_vendor_summary_test_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(payment_transactions.org_name) as org_name, max(category) as category, sum(amount_saved_daily) as amount_sent,
    max(date_registered) as date_registered FROM habahaba_trial.payment_transactions 
    RIGHT JOIN habahaba_trial.vendors ON payment_transactions.vendor_id=vendors.vendor_id
    GROUP BY category
    """)
    item = cur.fetchall()
    return json.dumps(item)


@app.route('/vendor-summary-json/', methods=['GET'])
@is_admin_logged_in
def a_vendor_summary_json():
    cur = mysql.connection.cursor()
    # cur.execute(
    #     f"""SELECT max(payments_table.org_name), max(category), sum(amount_sent) , max(date_registered)
    #     FROM habahaba_trial.payments_table INNER JOIN habahaba_trial.vendors ON payments_table.vendor_id = vendors.vendor_id
    #      group by category, payments_table.org_name""")
    cur.execute(f"""
        SELECT max(payment_transactions.org_name) as org_name, max(category) as category, sum(amount_saved_daily) as amount_sent,
        max(date_registered) as date_registered FROM habahaba_trial.payment_transactions 
        RIGHT JOIN habahaba_trial.vendors ON payment_transactions.vendor_id=vendors.vendor_id
        WHERE transaction_status = 1
        GROUP BY category
        """)
    vendor_summary = cur.fetchall()
    return datatable(vendor_summary)


@app.route('/float-summary-test-chart/', methods=['GET'])
def float_summary_test_chart():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT sum(redemption.quantity_redeemed) as quantity_redeemed, sum(amount_saved_daily) as amount_sent,
    sum(redemption.amount_redeemed) as amount_redeemed, sum((payment_transactions.saving_target / materials.price_per_kg) - redemption.amount_redeemed) as balance, count(*)
    FROM habahaba_trial.payment_transactions
    RIGHT JOIN habahaba_trial.redemption ON payment_transactions.payment_for=redemption.payment_for AND payment_transactions.vendor_id=redemption.vendor_id
    RIGHT JOIN habahaba_trial.materials ON payment_transactions.payment_for=material_id
    WHERE payment_transactions.vendor_id = {session['vendor_id']} AND transaction_status=1
    """)
    item = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT sum(amount_saved_daily) as amount_saved FROM habahaba_trial.payment_transactions WHERE vendor_id={session['vendor_id']}
    AND transaction_status=1
     """)
    amount_sent_daily = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT sum(quantity_redeemed) as quantity_redeemed, sum(amount_redeemed) as amount_redeemed
     FROM habahaba_trial.redemption WHERE vendor_id={session['vendor_id']}
    """)
    redemption_details = cur.fetchall()
    cur.close()

    amount_sent = amount_sent_daily[0]['amount_saved']
    amount_redeemed = redemption_details[0]['amount_redeemed']
    quantity_redeemed = redemption_details[0]['quantity_redeemed']

    final_value = [{
        'amount_sent': amount_sent,
        'amount_redeemed': amount_redeemed,
        'balance': int(amount_sent) - int(amount_redeemed)
    }]

    return json.dumps(final_value)


@app.route('/float-summary-chart/', methods=['GET'])
def float_summary_chart():
    cur = mysql.connection.cursor()
    cur.execute(
        f"""SELECT sum(quantity_redeemed) as quantity_redeemed, sum(amount_sent) as amount_sent ,
        sum(amount_redeemed) as amount_redeemed, sum(saving_target - payments_table.amount_redeemed) as balance 
        FROM habahaba_trial.payments_table WHERE vendor_id= '{session['vendor_id']}' """)
    summary_chart = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT sum(amount_saved_daily) as amount_saved FROM habahaba_trial.payment_transactions WHERE vendor_id={session['vendor_id']}
    AND transaction_status=1
     """)
    amount_sent_daily = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT sum(quantity_redeemed) as quantity_redeemed, sum(amount_redeemed) as amount_redeemed
     FROM habahaba_trial.redemption WHERE vendor_id={session['vendor_id']}
    """)
    redemption_details = cur.fetchall()
    cur.close()

    amount_sent = amount_sent_daily[0]['amount_saved']
    amount_redeemed = redemption_details[0]['amount_redeemed']
    quantity_redeemed = redemption_details[0]['quantity_redeemed']

    final_value = [{
        'amount_sent': amount_sent,
        'amount_redeemed': amount_redeemed,
        'balance': int(amount_sent) - int(amount_redeemed)
    }]
    return json.dumps(final_value)


# ADMIN PRODUCT VALIDATION
@app.route('/admin-product-validation/', methods=['POST', 'GET'])
@is_admin_logged_in
def product_validation():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials ORDER BY material_id DESC ")
    vendor_products = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        material_id = request.form['material_id']
        action_selected = request.form.get('action_selected')

        try:
            cur = mysql.connection.cursor()
            cur.execute("UPDATE habahaba_trial.materials SET material_status=%s WHERE material_id=%s",
                        (action_selected, material_id))
            mysql.connection.commit()
            cur.close()
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            flash("Error occured while changing status", "warning")
            return redirect(url_for('product_validation'))

        flash('Action completed successfully', 'success')
        return redirect(url_for('product_validation'))
    return render_template('admin_product_validation.html', vendor_products=vendor_products)


@app.route('/suspend-offer/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_suspend_offer():
    if request.method == 'POST':
        suspend_offer = 'Suspended'
        offer_id = request.form['offer_id']

        cur = mysql.connection.cursor()
        cur.execute(f"""
        UPDATE habahaba_trial.offers 
        SET offer_status=%s
        WHERE offer_id =%s
        """, (suspend_offer, offer_id))
        mysql.connection.commit()
        cur.close()
        flash('Offer suspended successfully', 'success')
        return redirect(url_for('admin_view_offers'))


@app.route('/suspend-product/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_suspend_product():
    if request.method == 'POST':
        suspend_offer = 'Suspended'
        product_id = request.form['product_id']

        cur = mysql.connection.cursor()
        cur.execute(f"""
        UPDATE habahaba_trial.materials 
        SET material_status=%s
        WHERE material_id =%s
        """, (suspend_offer, product_id))
        mysql.connection.commit()
        cur.close()
        flash('Product suspended successfully', 'success')
        return redirect(url_for('admin_view_products'))


# @app.route('/suspend-vendor/', methods=['POST', 'GET'])
# @is_admin_logged_in
# def admin_suspend_vendor():
#     if request.method == 'POST':
#         # account_type of -1 == suspended
#         suspend_offer = 'Suspended'
#         vendor_id = request.form['vendor_id']
#
#         cur = mysql.connection.cursor()
#         cur.execute(f"""
#         UPDATE habahaba_trial.vendors
#         SET account_type=%s
#         WHERE vendor_id =%s
#         """, (suspend_offer, vendor_id))
#         mysql.connection.commit()
#         cur.close()
#         flash('Vendor suspended successfully', 'success')
#         return redirect(url_for('admin_view_offers'))

@app.route('/pending-vendors-json/', methods=['GET'])
def pending_vendors_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT org_name, general_industry, acc_status FROM habahaba_trial.vendors WHERE acc_status != 'set_up'
    """)
    pending_vendors = cur.fetchall()
    cur.close()
    return datatable(pending_vendors)


# ADMIN VIEW VENDORS
@app.route('/admin-view-vendors/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_view_vendors():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.vendors")
    vendors = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.names")
    names = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        vendor_id = request.form['vendor_id']
        commission = request.form['commission']
        payment_method = request.form['payment_method']
        acc_number = request.form['acc_number']

        cur = mysql.connection.cursor()
        cur.execute("""
        UPDATE habahaba_trial.vendors
        SET commission=%s, payment_method=%s, acc_number=%s
        WHERE vendor_id=%s
        """, (
            commission, payment_method, acc_number, vendor_id
        ))
        mysql.connection.commit()
        cur.close()
        flash("Record Updated Successfully", "success")
        return redirect(url_for('admin_view_vendors'))
    return render_template('admin_view_vendors.html', vendors=vendors, names=names)


@app.route('/suspend-vendor/', methods=['POST'])
def admin_suspend_vendor():
    if request.method == 'POST':
        vendor_id = request.form['vendor_id']
        suspension_status = request.form['suspension_status']
        org_name = request.form['org_name']

        cur = mysql.connection.cursor()
        cur.execute(f"""
        UPDATE habahaba_trial.vendors 
        SET caution = '{suspension_status}'
        WHERE org_name = '{org_name}'
        """)
        mysql.connection.commit()
        cur.close()

        if suspension_status == 'Suspended':
            flash(f'{org_name} suspended successfully', 'success')
        elif suspension_status == 'Clear':
            flash('Suspension removed successfully', 'success')

        return redirect(url_for('admin_view_vendors'))
    return redirect(url_for('admin_view_vendors'))


# ADMIN VIEW PRODUCTS
@app.route('/admin-view-products/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_view_products():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials WHERE material_status = 'accepted'")
    products = cur.fetchall()
    cur.close()
    return render_template('admin_view_products.html', products=products)


# ADMIN VIEW OFFERS
@app.route('/admin-view-offers/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_view_offers():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.offers WHERE offer_status = 'accepted'")
    offers = cur.fetchall()
    cur.close()
    return render_template('admin_view_offers.html', offers=offers)


# ADMIN SET REGIONS
@app.route('/set-regions/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_set_regions():
    return render_template('admin_set_regions.html')


# ADMIN PRODUCT CATEGORIES
@app.route('/product-categories/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_product_categories():
    if request.method == 'POST':
        category_name = request.form['category_name']
        sub_category = request.form['sub_category']

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.category (category_name, sub_category) VALUES (%s, %s)", (
                category_name, sub_category
            ))
            mysql.connection.commit()
            cur.close()
            flash('Category added successfully', 'success')
            return redirect(url_for('admin_product_categories'))
        except MySQLdb.Error:
            flash('This Category already exists', 'danger')
            return redirect(url_for('admin_product_categories'))
    return render_template('admin-product-categories.html')


@app.route('/update-category/', methods=['POST'])
@is_admin_logged_in
def update_category():
    if request.method == 'POST':
        category_id = request.form['category_id']
        category_name = request.form['category']
        sub_category = request.form['sub_category']

        categories_counter = f"{category_name} {sub_category}"

        try:
            cur = mysql.connection.cursor()
            cur.execute("""
            UPDATE habahaba_trial.category 
            SET category_name=%s, sub_category=%s, category_counter=%s
            WHERE category_id=%s
            """, (
                category_name, sub_category, categories_counter, category_id
            ))
            mysql.connection.commit()
            cur.close()
            flash('Successfully changed category', 'success')
            return redirect(url_for('admin_product_categories'))

        except (MySQLdb.Error, MySQLdb.Warning) as e:
            print(e)
            flash('This category name already exists, Please enter a different one', 'danger')
            return redirect(url_for('admin_product_categories'))


@app.route('/delete-category/', methods=['POST'])
@is_admin_logged_in
def delete_category():
    if request.method == 'POST':
        category_id = request.form['category_id']

        cur = mysql.connection.cursor()
        cur.execute(f"DELETE FROM habahaba_trial.category WHERE category_id ='{category_id}' ")
        mysql.connection.commit()
        cur.close()
        flash("Category Deleted successfully", "success")
        return redirect(url_for('admin_product_categories'))


@app.route('/customer-summary/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_customer_summary():
    return render_template('a_customer_summary_report.html')


# admin delete product
# @app.route('/delete-product/<string:id_data>', methods=['POST', 'GET'])
# def delete_category(id_data):
#     cur = mysql.connection.cursor()
#     cur.execute("DELETE FROM habahaba_trial.materials WHERE material_id=%s" % id_data)
#     mysql.connection.commit()
#     return redirect(url_for('category'))

# @app.route('/customer-summary-test-json/', methods=['POST', 'GET'])
# @is_admin_logged_in
# def customer_summary_test_json():
#     cur = mysql.connection.cursor()
#     cur.execute(f"""
#     SELECT max(transaction_id) as transaction_id, max(concat_ws(' ', f_name, l_name)) as farmer_name,
#     max(location_of_land) as land_location, max(format((partnership.saving_target / (partnership.quantity_per_acre * partnership.price_per_kg)), 2)) as calc1,
#     max(format((partnership.saving_target / (partnership.quantity_per_acre * partnership.price_per_kg)), 2)) as calc2,
#     max(payment_transactions.org_name) as org_name, max(payment_transactions.category) as category, sum(amount_saved_daily) as amount_saved,
#     max(format(((amount_saved_daily / payment_transactions.saving_target) * 100), 2)) as calc3
#     FROM habahaba_trial.payment_transactions
#     RIGHT JOIN habahaba_trial.partnership ON payment_for=item_id
#     RIGHT JOIN habahaba_trial.users ON sender_id = user_id
#     RIGHT JOIN habahaba_trial.materials ON payment_for=material_id WHERE transaction_status = 1 GROUP BY payment_for
#     """)
#     items = cur.fetchall()
#     cur.close()
#     return json.dumps(items)


@app.route('/customer-summary-json/', methods=['POST', 'GET'])
@is_admin_logged_in
def customer_summary_json():
    cur = mysql.connection.cursor()
    # cur.execute(f"""
    # SELECT payment_id, sender_name, location_of_land,
    #  format((payments_table.saving_target / (quantity_per_acre * payments_table.price_per_kg)), 2),
    #  format((payments_table.saving_target / (quantity_per_acre * payments_table.price_per_kg)), 2),
    #  org_name, category, amount_sent, format(((amount_sent / saving_target) * 100), 2) FROM habahaba_trial.payments_table
    # INNER JOIN habahaba_trial.users ON sender_id = user_id
    # """)
    cur.execute(f"""
        SELECT max(transaction_id) as transaction_id, max(concat_ws(' ', f_name, l_name)) as farmer_name, 
        max(location_of_land) as land_location, max(format((partnership.saving_target / (partnership.quantity_per_acre * partnership.price_per_kg)), 2)) as calc1,
        max(format((partnership.saving_target / (partnership.quantity_per_acre * partnership.price_per_kg)), 2)) as calc2,
        max(payment_transactions.org_name) as org_name, max(payment_transactions.category) as category, sum(amount_saved_daily) as amount_saved,
        max(format(((amount_saved_daily / payment_transactions.saving_target) * 100), 2)) as calc3
        FROM habahaba_trial.payment_transactions 
        RIGHT JOIN habahaba_trial.partnership ON payment_for=item_id  
        RIGHT JOIN habahaba_trial.users ON sender_id = user_id
        RIGHT JOIN habahaba_trial.materials ON payment_for=material_id WHERE transaction_status = 1 GROUP BY payment_for
        """)
    user_details = cur.fetchall()
    cur.close()
    return datatable(user_details)


@app.route('/vendor-reports-json/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_vendor_reports_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT vendor_id,  org_name, sender_id, sender_name, amount_sent, saving_target,"
        " payment_for FROM habahaba_trial.payment_transactions")
    transactions = cur.fetchall()
    cur.close()
    return json.dumps(transactions)


@app.route('/admin-transactions-json/', methods=['GET'])
@is_admin_logged_in
def admin_transactions_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT max(concat_ws(' ', f_name, l_name)) as sender_name, max(phone_no) as sender_phone, "
        "max(org_name), sum(amount_saved_daily), max(sender_id),"
        " max(payment_for), max(transaction_id) FROM habahaba_trial.payment_transactions"
        " RIGHT JOIN habahaba_trial.users ON sender_id=user_id"
        " WHERE transaction_status=1 AND amount_saved_daily !=0 group by org_name, concat_ws(' ', f_name, l_name), payment_for, phone_no")
    transactions = cur.fetchall()
    cur.close()
    # return datatable(transactions)
    return datatable(transactions)


@app.route('/individual-json/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_individual_transactions_json():
    if request.method == 'POST':
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT sender_name, sender_phone, org_name, amount_sent, sender_id,"
            " payment_for FROM habahaba_trial.payment_transactions")
        transactions = cur.fetchall()
        cur.close()
        # return datatable(transactions)
        return datatable(transactions)


@app.route('/individual-transaction-json/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_individual_transactions_jsons(client_id):
    # client_id = request.form['client_id']

    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT sender_name, sender_phone, org_name, amount_saved_daily 
    FROM habahaba_trial.payment_transactions WHERE sender_id = '{client_id}'
    """)
    clients = cur.fetchall()
    cur.close()

    return datatable(clients)
    # return redirect(url_for('admin_individual_transactions'))


@app.route('/individual/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_individual_transactions():
    if request.method == 'POST':
        client_id = request.form['client_id']

        cur = mysql.connection.cursor()
        cur.execute(f"""
        SELECT sender_name, sender_phone, org_name, amount_saved_daily 
        FROM habahaba_trial.payment_transactions WHERE sender_id = '18'
        """)
        clients = cur.fetchall()
        cur.close()

        admin_individual_transactions_jsons(client_id)
        return redirect(url_for('admin_individual_transactions'))
    return render_template('admin_individual_transactions.html')


@app.route('/admin-view-categories/', methods=['GET'])
@is_admin_logged_in
def view_categories():
    cur = mysql.connection.cursor()
    cur.execute("SELECT category_id, category_name, sub_category FROM habahaba_trial.category")
    categories = cur.fetchall()
    cur.close()
    return datatable(categories)


counties = counties


@app.route('/regions-json/', methods=['GET'])
def regions_json():
    return counties


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[VENDOR DETAILS]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
# VENDOR LOGIN
@app.route('/vendor-login/', methods=['POST', 'GET'])
def vendor_login():
    if request.method == 'POST':
        phone_no = request.form['phone_no']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM habahaba_trial.vendors WHERE phone_no=%s", [phone_no])

        # current_vendor = cur.fetchone()
        # if current_vendor['caution'] == 'Suspended':
        #     return redirect(url_for('vendor_page_not_found'))
        if result > 0:
            data = cur.fetchone()
            password = data['passwords']
            # email = data['email']
            phone_no = data['phone_no']
            uid = data['vendor_id']
            f_name = data['f_name']
            l_name = data['l_name']
            payment_method = data['payment_method']
            acc_number = data['acc_number']
            org_name = data['org_name']
            location = data['location']
            # id_no = data['id_no']
            general_industry = data['general_industry']

            if bcrypt.checkpw(password_candidate.encode('utf-8'), password.encode('utf-8')):
                # if sha256_crypt.verify(password_candidate, password):
                session['vendor_logged_in'] = True
                session['vendor_id'] = uid
                # session['email'] = email
                session['f_name'] = f_name
                session['l_name'] = l_name
                session['payment_method'] = payment_method
                session['acc_number'] = acc_number
                session['org_name'] = org_name
                session['phone_no'] = phone_no
                session['location'] = location
                # session['id_no'] = id_no
                session['general_industry'] = general_industry
                x = '1'

                cur.execute("UPDATE habahaba_trial.vendors SET online=%s WHERE vendor_id=%s", (x, uid))

                action_performed = f'{f_name} {l_name} logged in'
                login_time = datetime.utcnow()
                success = 'Login success'

                cur.execute(f"""
                                INSERT INTO habahaba_trial.audit_report (vendor_id, action_performed, action_time, success) 
                                VALUES (%s, %s, %s, %s)
                                """, (
                    uid, action_performed, login_time, success
                ))
                mysql.connection.commit()
                return redirect(url_for('vendor_home'))
            else:
                flash('Incorrect password, please try again', 'danger')
                return render_template('vendor_login.html')
        else:
            flash('This phone number is not registered, please register first', 'danger')
            cur.close()
            return render_template('vendor_login.html')
    return render_template('vendor_login.html')


@app.route('/not-found/')
def vendor_page_not_found():
    return render_template('vendor_page_not_found.html')


# @app.route('/view-users/', methods=['GET'])
# def vendor_view_vendor_users():
#     cur = mysql.connection.cursor()
#     cur.execute(f"""
#     SELECT * FROM habahaba_trial.vendors WHERE org_name =
#     """)
#     return

@app.route('/view-users/', methods=['GET'])
def vendor_view_vendor_users():
    return render_template('vendor_view_vendors.html')


@app.route('/change-pin/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_change_password():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.vendors WHERE phone_no= '{session['phone_no']}'")
    vendors = cur.fetchone()
    pin = vendors['passwords']
    cur.close()

    if request.method == 'POST':
        current_pin = request.form['current_pin']
        new_pin = request.form['new_pin']
        confirm_pin = request.form['confirm_pin']

        if current_pin or new_pin != int:
            flash("Your pin should only contain numbers", "danger")
            return redirect(url_for('vendor_change_password'))
        if bcrypt.checkpw(current_pin.encode('utf-8'), pin.encode('utf-8')):
            if confirm_pin == new_pin:
                new_pin_value = bcrypt.hashpw(new_pin.encode('utf-8'), bcrypt.gensalt())

                cur = mysql.connection.cursor()
                cur.execute(f"""
                UPDATE habahaba_trial.vendors
                SET passwords = %s
                WHERE phone_no=%s
                """, (
                    new_pin_value, vendors['phone_no']
                ))
                mysql.connection.commit()
                cur.close()

                flash('Pin changed successfully', 'success')
                return redirect(url_for('vendor_change_password'))
            else:
                flash('Your new password and confirm password must match!', 'danger')
                return redirect(url_for('vendor_change_password'))
        else:
            flash('Wrong pin, please try again', 'danger')
            return redirect(url_for('vendor_change_password'))
    return render_template('vendor-change-password.html')


# VENDOR LOGOUT
@app.route('/vendor-logout/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_logout():
    if 'vendor_id' in session:
        cur = mysql.connection.cursor()
        uid = session['vendor_id']
        f_name = session['f_name']
        l_name = session['l_name']
        x = '0'
        cur.execute("UPDATE habahaba_trial.vendors SET online=%s WHERE vendor_id=%s ", (x, uid))

        success = 'Logged out successfully'
        logout_time = datetime.utcnow()
        action_performed = f'{f_name} {l_name} logged out'

        cur.execute(f"""
                INSERT INTO habahaba_trial.audit_report (vendor_id, action_performed, action_time, success) 
                VALUES (%s, %s, %s, %s)
                                """, (
            uid, action_performed, logout_time, success
        ))
        mysql.connection.commit()
        cur.close()

        session.clear()
        flash(f'You are now logged out {f_name}', 'danger')
        return redirect(url_for('vendor_login'))
    return redirect(url_for('vendor_login'))


# DELETE OFFERS
@app.route('/delete-offer/<string:id_data>', methods=['POST', 'GET'])
@is_vendor_logged_in
def delete_offer(id_data):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM habahaba_trial.offers WHERE offer_id=%s" % id_data)
    mysql.connection.commit()
    cur.close()
    flash('Offer removed successfully', 'orange lighten-1')
    return redirect(url_for('vendor_homepage'))


# VENDOR HOME
@app.route('/vendor-home/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_home():
    # vendor account
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT acc_status FROM habahaba_trial.vendors WHERE vendor_id = '{session['vendor_id']}'")
    acc_type = cur.fetchone()
    cur.close()

    if acc_type['acc_status'] != 'set_up':
        return redirect(url_for('vendor_not_set_up'))

    # clients
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT max(client_id) FROM habahaba_trial.partnership WHERE vendor_id = '{session['vendor_id']}' "
                f"GROUP BY client_id")
    users = cur.fetchall()
    cur.close()

    # products
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}'")
    products = cur.fetchall()
    cur.close()

    # offers
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.offers WHERE vendor_id = '{session['vendor_id']}' AND org_name = '{session['org_name']}'")
    offers = cur.fetchall()
    cur.close()

    # transactions
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.payment_transactions WHERE vendor_id = '{session['vendor_id']}'")
    transactions = cur.fetchall()
    cur.close()

    # status
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.vendors WHERE vendor_id = '{session['vendor_id']}'")
    status = cur.fetchone()
    cur.close()
    return render_template('vendor_home.html', users=users, products=products, offers=offers, transactions=transactions,
                           status=status, acc_type=acc_type)


@app.route('/not-set-up/')
@is_vendor_logged_in
def vendor_not_set_up():
    return render_template('vendor_account_not_set_up.html')


# VENDOR ADD ACCOUNT
@app.route('/add-user/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_add_account():
    password_pin = random.randint(1000, 9999)
    password = str(password_pin)
    date_registered = datetime.today()

    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.vendors WHERE vendor_id = '{session['vendor_id']}' ORDER BY vendor_id ")
    vendor = cur.fetchone()
    cur.close()

    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        gender = request.form.get('gender')
        phone_no = request.form['phone_no']
        id_no = request.form['id_no']
        account_type = request.form.get('account_type')
        location = request.form['location']
        passwords = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        commission = vendor['commission']
        payment_method = vendor['payment_method']
        acc_number = vendor['acc_number']
        org_name = vendor['org_name']
        general_industry = vendor['general_industry']
        acc_status = 'set_up'

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.vendors (f_name, l_name, gender, phone_no, commission, "
                        "payment_method, org_name, location, acc_number, acc_status, general_industry,"
                        " account_type, passwords, date_registered) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                            f_name, l_name, gender, phone_no, commission, payment_method, org_name, location,
                            acc_number, acc_status, general_industry, account_type, passwords, date_registered
                        ))
            mysql.connection.commit()
            cur.close()
            vendor_text_msg(phone_no, password)

            action_performed = f"{session['f_name']} {session['l_name']} added a user successfully"
            time_performed = datetime.utcnow()
            success = f'User if account type:{account_type} added successfully'
            additional_info = f"User: {f_name} {l_name}, phone number: {phone_no}"

            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.audit_report (vendor_id, action_performed, action_time, success, additional_details) 
            VALUES (%s, %s, %s, %s, %s)
                                                                """, (
                session['vendor_id'], action_performed, time_performed, success, additional_info
            ))
            mysql.connection.commit()
            cur.close()
            flash("New account added successfully", "success")
            return redirect(url_for('vendor_add_account'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            action_performed = f"{session['f_name']} {session['l_name']} tried adding a user"
            time_performed = datetime.utcnow()
            success = 'Failed to add user'
            additional_info = f"{e}"

            cur = mysql.connection.cursor()
            cur.execute(f"""
                        INSERT INTO habahaba_trial.audit_report (vendor_id, action_performed, action_time, success, additional_details) 
                        VALUES (%s, %s, %s, %s, %s)
            """, (
                session['vendor_id'], action_performed, time_performed, success, additional_info
            ))
            mysql.connection.commit()
            cur.close()
            flash("This phone number already exists, please enter another phone number", "warning")
    return render_template('vendor_add_account.html')


@app.route('/categories-json/', methods=['GET'])
@is_vendor_logged_in
def v_categories_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT category_id, category_name FROM habahaba_trial.category
    """)
    category_id = cur.fetchall()
    cur.close()
    return json.dumps(category_id)


# VENDOR PRODUCT VERIFICATION
@app.route('/product-setup/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_product_verification():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.category")
    categories = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        vendor_name = request.form['vendor_name']
        vendor_id = request.form['vendor_id']
        vendor_email = request.form['vendor_email']
        category = request.form.get('category')
        price_per_kg = request.form['price_per_kg']
        quantity_per_acre = request.form['quantity_per_acre']
        phone_no = request.form['phone_no']
        location = request.form['location']
        org_name = request.form['org_name']
        item_name = request.form['item_name']
        category_id = request.form['category_id']
        vendor_crop_counter = f"{vendor_name} {item_name}"

        regions = request.form.getlist('region_available')
        region = ','.join(regions)

        if 'Country Wide' in region and len(region) > 12:
            flash('Country Wide cannot be selected with another region', 'warning')
            return redirect(url_for('vendor_product_verification'))
        material_status = 'pending'

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.materials(vendor_id, vendor_name, vendor_email, crop_name,"
                        " quantity_per_acre, price_per_kg, phone_no, location, org_name, vendor_crop_counter, category,"
                        " region, material_status, category_id)"
                        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                            vendor_id, vendor_name, vendor_email, item_name, quantity_per_acre, price_per_kg, phone_no,
                            location, org_name, vendor_crop_counter, category, region, material_status, category_id
                        ))
            mysql.connection.commit()
            cur.close()
            flash('Product submitted successfully', 'success')

            action_performed = f"{session['f_name']} {session['l_name']} requested to add a product"
            time_performed = datetime.utcnow()
            success = 'Requested to add a product successfully'

            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.audit_report (vendor_id, action_performed, action_time, success) 
            VALUES (%s, %s, %s, %s)
                                        """, (
                session['vendor_id'], action_performed, time_performed, success
            ))
            mysql.connection.commit()
            cur.close()

            return redirect(url_for('vendor_product_verification'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:

            action_performed = f"{session['f_name']} {session['l_name']} requested to add a product failed"
            time_performed = datetime.utcnow()
            success = 'Request to add product Failed'
            additional_info = f"{e}"

            cur = mysql.connection.cursor()
            cur.execute(f"""
                        INSERT INTO habahaba_trial.audit_report (vendor_id, action_performed, action_time, success, additional_details) 
                        VALUES (%s, %s, %s, %s, %s)
                                                    """, (
                session['vendor_id'], action_performed, time_performed, success, additional_info
            ))
            mysql.connection.commit()
            cur.close()
            flash('Product already exists', 'danger')
            return redirect(url_for('vendor_product_verification'))
    return render_template('vendor_product_verification.html', categories=categories)


# VENDOR LIST
@app.route('/clients-list/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_partners():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.partnership WHERE vendor_id = '{session['vendor_id']}'")
    partners = cur.fetchall()
    cur.close()
    return render_template('vendor-partners.html', partners=partners)


# VENDOR CLIENT ONBOARDING
@app.route('/client-registration/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_user_onboarding():
    password_pin = random.randint(1000, 9999)
    password = str(password_pin)
    date_registered = datetime.today()

    cur = mysql.connection.cursor()
    cur.execute("SELECT county_name FROM habahaba_trial.counties WHERE county_name != 'Country Wide'")
    county_list = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        gender = request.form.get('gender')
        phone_no = request.form['phone_no']
        email = request.form['email']
        land_location = request.form['land_location']
        size_of_land = request.form['size_of_land']
        passwords = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        if int(size_of_land) <= 10:
            scale = 'Small Scale'
        else:
            scale = 'Large Scale'
        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.users (f_name, l_name, gender, phone_no, email,"
                        " password, date_registered, size_of_land, location_of_land, land_scale) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (f_name, l_name, gender, phone_no, email, passwords, date_registered, size_of_land,
                         land_location, scale))
            mysql.connection.commit()

            vendor_text_msg(phone_no, password)

            action_performed = f"{session['f_name']} {session['l_name']} onboarded {f_name} {l_name}"
            time_performed = datetime.utcnow()
            success = "Successfully onboarded a farmer"

            cur.execute(f"""
                            INSERT INTO habahaba_trial.audit_report (vendor_id, action_performed, action_time, success) 
                            VALUES (%s, %s, %s, %s)
                            """, (
                session['vendor_id'], action_performed, time_performed, success
            ))
            mysql.connection.commit()
            cur.close()

            flash(f'User will receive your password on {phone_no} ', 'success')
            return redirect(url_for('vendor_user_onboarding'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            action_performed = f"{session['f_name']} {session['l_name']} tried to onboard a user"
            time_performed = datetime.utcnow()
            success = "Failed to onboard a farmer."
            additional_details = f"{e}"

            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.audit_report (vendor_id, action_performed, action_time, success, additional_details) 
            VALUES (%s, %s, %s, %s, %s)
                                        """, (
                session['vendor_id'], action_performed, time_performed, success, additional_details
            ))
            mysql.connection.commit()
            cur.close()
            flash('This use already exists, please try another one', 'danger')
            return redirect(url_for('vendor_user_onboarding'))
    return render_template('vendor_user_onboarding.html', county_list=county_list)


# VENDOR OFFER LIST
@app.route('/vendor-offer-list/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_offer_list():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.offers WHERE vendor_id = '{session['vendor_id']}' ORDER BY offer_id DESC ")
    offers = cur.fetchall()
    cur.close()
    return render_template('vendor-offers.html', offers=offers)


# VENDOR CHARTS
@app.route('/vendor-chart/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_chart():
    return render_template('vendor_chart.html')


@app.route('/chart-tutorial/', methods=['POST', 'GET'])
def chart_tutorial():
    cur = mysql.connection.cursor()
    cur.execute("SELECT amount_sent, saving_target FROM habahaba_trial.payment_transactions")
    ratio = cur.fetchone()
    cur.close()
    return render_template('chartjs_tutorial.html', ratio=ratio)


# VENDOR USER TRANSACTIONS
@app.route('/user-transactions/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_user_transactions():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT sender_name, sender_phone, amount_sent, saving_target, date_and_time FROM"
        f" habahaba_trial.payment_transactions WHERE vendor_id = '{session['vendor_id']}'")
    transactions = cur.fetchall()
    cur.close()
    return render_template('vendor_user_transactions.html', transactions=transactions)


# VENDOR USER ONBOARDING
@app.route('/mass-onboarding/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_mass_onboarding():
    if request.method == 'POST':
        csv_file = request.files['csv_file']

        if csv_file and csv_file.filename.endswith('.csv'):
            my_file = csv.reader(csv_file)
            next(my_file)

            for row in my_file:
                cur = mysql.connection.cursor()
                cur.execute("INSERT INTO habahaba_trial.names (f_names, gender) VALUES (%s, %s)",
                            row)
                mysql.connection.commit()
                cur.close()

        # for first in csv_file:
        #     for inner_row in first:
        #         print(inner_row)
        #         cur = mysql.connection.cursor()
        #         cur.execute("""
        #         INSERT INTO habahaba_trial.names (f_names, gender) VALUES (%s, %s)
        #         """, (first[0], first[0]))
        #         mysql.connection.commit()
        #         cur.close()
        flash("Sent successfully", "success")
        return redirect(url_for('vendor_user_onboarding'))
    # return render_template('vendor_mass_onboarding.html')


# VENDOR CLIENT LIST
@app.route('/client-list/', methods=['GET'])
def client_list():
    # all a member's clients
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.partnership WHERE vendor_id = '{session['vendor_id']}' ")
    users = cur.fetchall()
    cur.close()
    return render_template('vendor_client_list.html')


# VENDOR PRODUCTS
@app.route('/vendor-products/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_products():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}' AND material_status = 'accepted' ")
    products = cur.fetchall()
    cur.close()
    return render_template('vendor-products.html', products=products)


# DELETE VENDOR PRODUCTS
@app.route('/vendor-delete-products', methods=['POST'])
@is_vendor_logged_in
def delete_products():
    if request.method == 'POST':
        material_id = request.form['material_id']
        crop_name = request.form['material']

        cur = mysql.connection.cursor()
        cur.execute(f"DELETE FROM habahaba_trial.materials WHERE material_id= {material_id}")
        mysql.connection.commit()
        cur.close()

        flash(f'{crop_name} deleted successfully', 'success')
        return redirect(url_for('vendor_products'))
    return redirect(url_for('vendor_products'))


# VENDOR OFFER LIST
@app.route('/vendor-offers/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendors_offer_list():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}' AND material_status = 'accepted'")
    products = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.offers WHERE vendor_id = '{session['vendor_id']}' AND offer_status = 'Accepted'")
    offers = cur.fetchall()
    cur.close()

    today = datetime.today()

    if request.method == 'POST':
        vendor_name = request.form['vendor_name']
        # vendor_email = request.form['vendor_email']
        org_name = request.form['org_name']
        offer_name = request.form.get('offer_name')
        percentage_off = request.form['percentage_off']
        valid_until = request.form['valid_until']
        vendor_id = session['vendor_id']
        campaign_name = request.form['campaign_name']
        material_id = request.form['material_ids']

        region_available = request.form.getlist('region_available')
        region = ','.join(region_available)

        offer_status = 'Pending'

        if region == '':
            flash('Please select a region where your offer will be available', 'warning')
            return redirect(url_for('vendors_offer_list'))

        try:
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO habahaba_trial.offers (vendor_name, vendor_id,  org_name, offer_name, percentage_off"
                ", valid_until, region_available, active_from, offer_status, campaign_name, material_ids) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                    vendor_name, vendor_id, org_name, offer_name, percentage_off, valid_until, region, today,
                    offer_status, campaign_name, material_id
                ))
            mysql.connection.commit()
            cur.close()

            action_performed = f"{session['f_name']} {session['l_name']} requested to add a product"
            time_performed = datetime.utcnow()
            success = 'Requested to add an offer successfully'

            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.audit_report (vendor_id, action_performed, action_time, success) 
            VALUES (%s, %s, %s, %s)
                                                                """, (
                session['vendor_id'], action_performed, time_performed, success
            ))
            flash('Offer submitted successfully', 'success')
            return redirect(url_for('vendors_offer_list'))

        except(MySQLdb.Error, MySQLdb.Warning) as e:
            action_performed = f"{session['f_name']} {session['l_name']} requested to add a product"
            time_performed = datetime.utcnow()
            success = 'Requested to add an offer Failed'
            additional_info = f"{e}"

            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.audit_report (vendor_id, action_performed, action_time, success, additional_details) 
            VALUES (%s, %s, %s, %s, %s)
                                                    """, (
                session['vendor_id'], action_performed, time_performed, success, additional_info
            ))
            mysql.connection.commit()
            cur.close()

            flash("Failed to submit offer", "danger")
            return redirect(url_for('vendor_offer_list'))
    return render_template('vendors-offers.html', products=products, offers=offers, counties=counties)


@app.route('/float-summary/', methods=['GET'])
@is_vendor_logged_in
def v_float_summary():
    return render_template('a_float_summary.html')


@app.route('/float-summary-json/', methods=['GET'])
@is_vendor_logged_in
def v_float_summary_json():
    cur = mysql.connection.cursor()
    # cur.execute(f"""
    # SELECT sum(redemption.quantity_redeemed) as quantity_redeemed, sum(amount_saved_daily) as amount_saved,
    # sum(redemption.amount_redeemed) as amount_redeemed, sum(amount_saved_daily - payment_transactions.amount_redeemed)
    # FROM habahaba_trial.redemption RIGHT JOIN habahaba_trial.payment_transactions ON redemption.vendor_id = payment_transactions.vendor_id
    # WHERE redemption.vendor_id = '{session['vendor_id']}'
    # """)
    # summary = cur.fetchall()
    # cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT sum(amount_saved_daily) as amount_saved_daily FROM habahaba_trial.payment_transactions
     WHERE vendor_id = {session['vendor_id']} AND transaction_status = 1
    """)
    amount_saved = cur.fetchall()

    cur.execute(f"""
    SELECT sum(amount_redeemed) as amount_redeemed, sum(quantity_redeemed) as quantity_redeemed
     FROM habahaba_trial.redemption WHERE vendor_id = {session['vendor_id']}
    """)
    redemption_details = cur.fetchall()
    cur.close()

    amount_saved_daily = amount_saved[0]['amount_saved_daily']
    amount_redeemed = redemption_details[0]['amount_redeemed']
    quantity_redeemed = redemption_details[0]['quantity_redeemed']

    final_value = [{
        'quantities_redeemed': int(amount_saved_daily),
        'amount_saved_daily': int(amount_saved_daily),
        'amount_redeemed': amount_redeemed,
        'balance': int(amount_saved_daily) - int(amount_redeemed)
    }]

    # print(final_value)

    return datatable(final_value)


@app.route('/free-trial/', methods=['GET'])
@is_vendor_logged_in
def free_trial():
    cur = mysql.connection.cursor()
    # cur.execute(f"""
    #     SELECT sum(redemption.quantity_redeemed) as quantity_redeemed, sum(amount_saved_daily) as amount_saved_daily,
    #     sum(redemption.amount_redeemed), sum(amount_saved_daily - redemption.amount_redeemed)
    #       FROM habahaba_trial.payment_transactions
    #       RIGHT JOIN habahaba_trial.redemption ON payment_transactions.vendor_id = redemption.vendor_id
    #       WHERE payment_transactions.vendor_id = '{session['vendor_id']}' AND transaction_status = 1
    #     """)

    cur.execute(f"""
    SELECT sum(amount_saved_daily) as amount_saved_daily FROM habahaba_trial.payment_transactions
    """)
    amount_saved_daily = cur.fetchall()
    # print(amount_saved_daily[0]['amount_saved_daily'])
    cur.execute(f"""
        SELECT sum(amount_redeemed) as amount_redeemed FROM habahaba_trial.redemption
        """)
    amount_redeemed = cur.fetchall()
    # print(amount_redeemed[0]['amount_redeemed'])
    # value = {'amount_saved_daily': amount_saved_daily['amount_saved_daily'],
    #          'amount_redeemed': amount_redeemed['amount_redeemed']}
    value = {'amount_saved_daily': amount_saved_daily[0]['amount_saved_daily'],
             'amount_redeemed': amount_redeemed[0]['amount_redeemed']}
    # print(value)

    cur.execute(f"""
    SELECT SUM(amount_saved_daily) as amount_saved_daily, SUM(redemption.amount_redeemed) as amount_redeemed, 
    SUM(redemption.quantity_redeemed) as quantity_redeemed , max(redemption.payment_for) as payment_for
     FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.redemption ON redemption.vendor_id = payment_transactions.vendor_id 
    WHERE payment_transactions.vendor_id = '{session['vendor_id']}' GROUP BY redemption.payment_for
    """)
    summary = cur.fetchall()
    cur.close()
    return json.dumps(summary)


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[JSON FILES]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
# vendor-jsons
@app.route('/transactions-json/', methods=['POST', 'GET'])
@is_admin_logged_in
def transactions_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.vendors")
    vendors = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials")
    materials = cur.fetchall()
    cur.close()
    return jsonify({"materials": materials}, {"vendors": vendors})


@app.route('/client-list-json/', methods=['GET'])
@is_vendor_logged_in
def client_list_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT user_id, CONCAT_WS(' ', f_name, l_name) as client_name, email as client_email, users.phone_no as client_phone, 
    crop_name as vendor_crop
     FROM habahaba_trial.partnership RIGHT JOIN habahaba_trial.users ON client_id=user_id
      RIGHT JOIN habahaba_trial.materials on item_id=material_id
     WHERE partnership.vendor_id = '{session['vendor_id']}'
    """)
    users = cur.fetchall()
    cur.close()
    return datatable(users)


@app.route('/vendor-partners-json/', methods=['GET'])
@is_vendor_logged_in
def vendor_partners_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(CONCAT_WS(' ', f_name, l_name)) as client_name, max(users.phone_no), max(crop_name) FROM habahaba_trial.partnership
     RIGHT JOIN habahaba_trial.materials ON item_id=material_id RIGHT JOIN habahaba_trial.users ON user_id=client_id
     WHERE materials.vendor_id = '{session['vendor_id']}' GROUP BY users.phone_no, crop_name
    """)
    # cur.execute(
    #     f"SELECT  max(client_name), max(client_phone), max(vendor_crop) FROM habahaba_trial.partnership"
    #     f" WHERE vendor_id = '{session['vendor_id']}' GROUP BY client_name")
    partners = cur.fetchall()
    cur.close()
    return datatable(partners)


@app.route('/vendor-user-transactions-json/', methods=['GET'])
@is_vendor_logged_in
def vendor_user_transactions_json():
    # sender_name, sender_email, sender_phone, amount_sent, saving_target, date_sent
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT sender_name, sender_phone, amount_sent, saving_target, date_and_time FROM"
        f" habahaba_trial.payment_transactions WHERE vendor_id = '{session['vendor_id']}'")
    transactions = cur.fetchall()
    cur.close()
    return datatable(transactions)


@app.route('/vendor-products-json/', methods=['GET'])
@is_vendor_logged_in
def vendor_products_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"""SELECT material_id, crop_name, quantity_per_acre, price_per_kg FROM habahaba_trial.materials 
        WHERE vendor_id = '{session['vendor_id']}' AND material_status = 'accepted' 
            ORDER BY material_id DESC """)

    products = cur.fetchall()
    cur.close()
    return datatable(products)


@app.route('/admin-view-vendor-products-json/', methods=['GET'])
@is_admin_logged_in
def admin_view_vendor_products_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT material_id, org_name, crop_name, location, quantity_per_acre, price_per_kg, "
        "material_status  FROM habahaba_trial.materials")
    materials = cur.fetchall()
    cur.close()
    return datatable(materials)


@app.route('/validate-offers/', methods=['POST', 'GET'])
@is_admin_logged_in
def validate_offers():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.offers ORDER BY offer_id AND offer_status ")
    all_offers = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        offer_id = request.form['offer_id']
        offer_status = request.form.get('offer_status')

        cur = mysql.connection.cursor()
        cur.execute("""
        UPDATE habahaba_trial.offers
        SET offer_status = %s
        WHERE offer_id = %s
        """,
                    (offer_status, offer_id))
        mysql.connection.commit()
        cur.close()
        flash('Status changed successfully', 'success')
        return redirect(url_for('validate_offers'))
    return render_template('admin_offer_validation.html', all_offers=all_offers)


@app.route('/admin-categories-json/', methods=['GET'])
@is_admin_logged_in
def admin_categories_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT category_id, category_name, sub_category FROM habahaba_trial.category")
    categories = cur.fetchall()
    cur.close()
    return datatable(categories)


@app.route('/user-transactions-json/', methods=['GET'])
def user_transactions_json():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT sender_name, sender_phone, amount_sent, saving_target, date_and_time"
                f" FROM habahaba_trial.payment_transactions WHERE vendor_id = '{session['vendor_id']}'")
    transactions = cur.fetchall()
    cur.close()
    return datatable(transactions)


@app.route('/vendor-offer-list-json/', methods=['GET'])
@is_vendor_logged_in
def vendor_offer_list_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT offer_name, percentage_off, region_available, valid_until, offer_status "
        f"FROM habahaba_trial.offers WHERE vendor_id = '{session['vendor_id']}' ORDER BY offer_id DESC ")
    offers = cur.fetchall()
    cur.close()
    return datatable(offers)


@app.route('/counties-json/', methods=['POST', 'GET'])
def counties_json():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.counties")
    county = cur.fetchall()
    cur.close()
    return json.dumps(county)


@app.route('/set-counties-json/', methods=['GET'])
def set_counties_json():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT county_id, county_name FROM habahaba_trial.counties")
    county = cur.fetchall()
    cur.close()
    return datatable(county)


@app.route('/add-counties-json/', methods=['POST'])
def add_counties_json():
    if request.method == 'POST':
        county_name = request.form['county_name']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.counties (county_name) VALUES (%s)", (county_name,))
        mysql.connection.commit()
        cur.close()

        flash("Region added successfully", "success")
        return redirect(url_for('admin_set_regions'))


@app.route('/vendors-home-json/', methods=['POST', 'GET'])
@is_vendor_logged_in
def vendor_home_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT vendor_id, org_name, account_type, acc_status FROM habahaba_trial.vendors WHERE vendor_id = '{session['vendor_id']}'")
    vendor = cur.fetchone()
    cur.close()
    return json.dumps(vendor)


@app.route('/products-json/', methods=['POST', 'GET'])
@is_vendor_logged_in
def products_json():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}'")
    products = cur.fetchall()
    cur.close()
    return json.dumps(products)


@app.route('/chart-json/', methods=['POST', 'GET'])
def chart_json():
    cur = mysql.connection.cursor()
    # cur.execute("SELECT sender_name, sender_phone, amount_sent, org_name FROM habahaba_trial.payments_table")
    cur.execute(
        "SELECT max(category) as category, sum(amount_sent) as amount_sent FROM habahaba_trial.payment_transactions GROUP BY category")
    items = cur.fetchall()
    cur.close()
    return json.dumps(items)


@app.route('/view-users-json/', methods=['GET'])
@is_admin_logged_in
def view_users_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT f_name, l_name, gender, phone_no, location_of_land FROM habahaba_trial.users")
    users = cur.fetchall()
    cur.close()
    return datatable(users)


@app.route('/admin-view-offers-json/', methods=['GET'])
@is_admin_logged_in
def admin_view_offers_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT offer_id, org_name, offer_name, percentage_off, valid_until, region_available"
                " FROM habahaba_trial.offers WHERE offer_status = 'accepted' ORDER BY offer_id DESC")
    offers = cur.fetchall()
    cur.close()
    return datatable(offers)


# @app.route('/user-vendor-json/', methods=['GET'])
# def user_vendor_json():
#     cur = mysql.connection.cursor()
#     cur.execute("SELECT f_name, l_name, gender, phone_no, id_no, email FROM habahaba_trial.users")
#     users = cur.fetchall()
#     cur.close()


@app.route('/admin-vendors-json/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_view_vendors_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT max(vendor_id), max(org_name), max(general_industry), max(location), max(commission),"
        " max(caution), max(payment_method), max(acc_number), max(acc_status)"
        " FROM habahaba_trial.vendors GROUP BY org_name, acc_status")
    vendors = cur.fetchall()
    cur.close()
    return datatable(vendors)


@app.route('/admin-view-products-json/', methods=['GET'])
@is_admin_logged_in
def admin_view_products_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT material_id, org_name, crop_name, quantity_per_acre, price_per_kg, region"
        " FROM habahaba_trial.materials WHERE material_status = 'accepted'")
    products = cur.fetchall()
    cur.close()
    return datatable(products)


@app.route("/mysql-errors/", methods=['GET'])
def mysql_errors():
    cur = mysql.connection.cursor()
    cur.execute("SHOW ERRORS")
    errors = cur.fetchall()
    cur.close()

    return json.dumps(errors)


@app.route('/admin-action-offers-json/', methods=['GET'])
@is_admin_logged_in
def admin_action_offers_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT offer_id, org_name, offer_name, percentage_off, valid_until, offer_status"
                " FROM habahaba_trial.offers ORDER BY offer_id DESC")
    offers = cur.fetchall()
    cur.close()
    return datatable(offers)


@app.route('/offers-json/', methods=['POST', 'GET'])
def offers_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.offers WHERE offer_status = 'accepted' ORDER BY offer_id DESC ")
    offers = cur.fetchall()
    cur.close()
    return json.dumps(offers)


# TRIAL 2 ON OFFERS JSON
@app.route('/offers-list-json/', methods=['POST', 'GET'])
def offers_list_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.offers WHERE offer_status = 'accepted' ORDER BY offer_id DESC ")
    offer_list = cur.fetchall()
    cur.close()
    return json.dumps(offer_list)


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[CLIENTS DETAILS]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
# @app.route('/client-onboarding/', methods=['POST', 'GET'])
# def client_onboarding():
#     if request.method == 'POST':
#         f_name = request.form['f_name']
#         l_name = request.form['l_name']
#         gender = request.form.get('gender')
#         age = request.form['age']
#         phone_no = request.form['phone_no']
#         id_no = request.form['id_no']
#         email = request.form['email']
#         password = sha256_crypt.encrypt(str(request.form['password']))
#
#         try:
#             cur = mysql.connection.cursor()
#             cur.execute("INSERT INTO habahaba_trial.users (f_name, l_name, gender, age, phone_no, id_no, email,"
#                         " password) "
#                         "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
#                         (f_name, l_name, gender, age, phone_no, id_no, email, password))
#             mysql.connection.commit()
#             cur.close()
#             flash(f'User will receive their password on {phone_no} ', 'success')
#             return redirect(url_for('client_onboarding'))
#
#         except(MySQLdb.Error, MySQLdb.Warning) as e:
#             flash('This email already exists, please try another one', 'warning')
#             return redirect(url_for('client_onboarding'))
#     return render_template('client_onboarding.html')


@app.route('/example/', methods=['POST', 'GET'])
def example():
    return render_template('example.html')


@app.route('/user-registration/', methods=['POST', 'GET'])
def user_registration():
    password_pin = random.randint(1000, 9999)
    password = str(password_pin)
    date_registered = datetime.today()

    cur = mysql.connection.cursor()
    cur.execute("SELECT county_name FROM habahaba_trial.counties WHERE county_name != 'Country Wide'")
    county_list = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        gender = request.form.get('gender')
        age = request.form['age']
        phone_no = request.form['phone_no']
        size_of_land = request.form['size_of_land']
        land_location = request.form['land_location']
        email = request.form['email']
        passwords = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        # password = sha256_crypt.encrypt(str(request.form['password']))

        if int(size_of_land) < 10:
            scale = 'Small Scale'
        else:
            scale = 'Large Scale'

        try:
            text_msg(phone_no, password)
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.users (f_name, l_name, gender, age, phone_no, size_of_land, email,"
                        " password, date_registered, location_of_land, land_scale) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (f_name, l_name, gender, age, phone_no, size_of_land, email, passwords, date_registered,
                         land_location, scale))
            mysql.connection.commit()
            cur.close()
            flash(f'You will receive your password on {phone_no} ', 'green lighten-4')
            return redirect(url_for('user_registration'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            flash('This user already exists', 'red lighten-2')
            return redirect(url_for('user_registration'))
    return render_template('user_registration.html', county_list=county_list)


# @app.route('/', methods=['POST', 'GET'])
# def login_page():
#     return render_template('user_login.html')


# @app.route('/user-login/', methods=['POST', 'GET'])
@app.route('/', methods=['POST', 'GET'])
def user_login():
    if request.method == 'POST':
        phone_no = request.form['phone_no']
        password_candidate = request.form['password']
        print(phone_no, password_candidate)

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM habahaba_trial.users WHERE phone_no=%s", [phone_no])
        print(result)

        if result > 0:
            data = cur.fetchone()
            password = data['password']
            email = data['email']
            uid = data['user_id']
            f_name = data['f_name']
            l_name = data['l_name']
            id_no = data['id_no']
            phone_no = data['phone_no']

            if bcrypt.checkpw(password_candidate.encode('utf-8'), password.encode('utf-8')):
                # if sha256_crypt.verify(password_candidate, password):
                session['user_logged_in'] = True
                session['user_id'] = uid
                session['email'] = email
                session['f_name'] = f_name
                session['l_name'] = l_name
                session['id_no'] = id_no
                session['phone_no'] = phone_no
                x = '1'

                payload = {
                    'username': f_name,
                    'exp': datetime.utcnow() + timedelta(minutes=5)
                }

                jwt_token = jwt.encode(payload, 'secret', algorithm='HS256')
                token = jwt.decode(jwt_token, 'secret', algorithms='HS256')

                print(jwt_token, payload)
                # decoded_token = jwt.decode(jwt_token, 'secret', algorithms='HS256')
                # print(decoded_token)
                # headers = {'Authorization': 'Bearer ' + jwt_token}
                # response = requests.get(headers=headers)
                # encoded = jwt.encode(
                #     {'some': 'payload'},
                #     'secret',
                #     algorithm='HS256'
                # )
                # encoded.de
                # print(encoded)
                # the_response = make_response()
                # the_response.set_cookie('jwt', encoded)
                # print(the_response)

                cur.execute("UPDATE habahaba_trial.users SET online=%s WHERE user_id=%s", (x, uid))
                action_performed = f'{f_name} {l_name} logged in successfully'
                login_time = datetime.utcnow()
                success = f'Login success'

                cur.execute(f"""
                                INSERT INTO habahaba_trial.audit_report (sender_id, action_performed, action_time, success) 
                                VALUES (%s, %s, %s, %s)
                                """, (
                    uid, action_performed, login_time, success
                ))
                mysql.connection.commit()

                return redirect(url_for('ukulima'))
                # return jsonify({'token': jwt_token})
            else:
                flash('Incorrect password, please try again', 'red lighten-2')
                return render_template('user_login.html')
            # return jsonify({'message': 'Failed to login: Username -Password pair do not match'})
        else:
            flash('This phone number is not registered', 'red lighten-2')
            cur.close()
            return render_template('user_login.html')
    return render_template('user_login.html')


@app.route('/change-password/', methods=['POST', 'GET'])
@is_user_logged_in
def user_change_password():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.users WHERE phone_no = '{session['phone_no']}'")
    user = cur.fetchone()

    pin = user['password']
    cur.close()

    if request.method == 'POST':
        current_pin = request.form['current_pin']
        new_pin = request.form['new_pin']
        confirm_pin = request.form['confirm_pin']

        if current_pin or new_pin != int:
            flash('Password should ony contain numbers', 'red lighten-2')
            return redirect(url_for('user_change_password'))

        # passwords = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        if bcrypt.checkpw(current_pin.encode('utf-8'), pin.encode('utf-8')):
            if confirm_pin == new_pin:
                new_pin_value = bcrypt.hashpw(new_pin.encode('utf-8'), bcrypt.gensalt())
                cur = mysql.connection.cursor()
                cur.execute(f"""
                UPDATE habahaba_trial.users 
                SET password=%s
                WHERE phone_no=%s
                """, (
                    new_pin_value, user['phone_no']
                ))
                mysql.connection.commit()
                cur.close()
                flash('Password Updated Successfully', 'green lighten-2')
                return redirect(url_for('user_change_password'))
            else:
                flash('New pin and confirm pin were not the same', 'red lighten-2')
                return redirect(url_for('user_change_password'))
        else:
            flash('The password does not match', 'red lighten-2')
            return redirect(url_for('user_change_password'))
    return render_template('user-change-password.html')


@app.route('/logout/', methods=['POST', 'GET'])
@is_user_logged_in
def user_logout():
    if 'user_id' in session:
        cur = mysql.connection.cursor()
        cur.execute(f"DELETE FROM habahaba_trial.redirecting_table WHERE client_id = '{session['user_id']}'")
        mysql.connection.commit()
        cur.close()
        # cur.execute("DELETE FROM habahaba_trial.partnership WHERE partnership_id=%s" % id_data)

        cur = mysql.connection.cursor()
        uid = session['user_id']
        f_name = session['f_name']
        l_name = session['l_name']
        x = '0'
        cur.execute("UPDATE habahaba_trial.users SET online=%s WHERE user_id=%s ", (x, uid))

        success = 'Logged out successfully'
        logout_time = datetime.utcnow()
        action_performed = f'{f_name} {l_name} logged out'

        cur.execute(f"""
                INSERT INTO habahaba_trial.audit_report (sender_id, action_performed, action_time, success) 
                VALUES (%s, %s, %s, %s)
                                """, (
            uid, action_performed, logout_time, success
        ))
        mysql.connection.commit()
        session.clear()
        flash(f'You are now logged out {f_name}', 'red lighten-2')
        return redirect(url_for('user_login'))
    return redirect(url_for('user_login'))


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[service worker registration]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
@app.route('/sw.js', methods=['GET'])
def sw():
    return current_app.send_static_file('sw.js')


# @app.route('/ukulima-targets-test-json/', methods=['GET'])
# @is_user_logged_in
# def targets_test_json():
#     cur = mysql.connection.cursor()
#     cur.execute(f"""
#         SELECT max(crop_name) as payment_for, sum(amount_saved_daily) as amount_sent, max(payment_transactions.saving_target),
#         max(payment_transactions.org_name) as org_name, max(partnership.price_per_kg) as price_per_kg
#         FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.partnership ON payment_for = item_id
#         RIGHT JOIN habahaba_trial.materials ON payment_for = material_id
#          WHERE sender_id = {session['user_id']}  GROUP BY payment_for
#         """)
#     items = cur.fetchall()
#     cur.close()
#     return json.dumps(items)


# CLIENT LOGIN
@app.route('/ukulima/', methods=['POST', 'GET'])
@is_user_logged_in
def ukulima():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.wallet WHERE client_id = '{session['user_id']}' ORDER BY transaction_id DESC ")
    current_balance = cur.fetchone()
    cur.close()

    # get the crops a user currently has
    cur = mysql.connection.cursor()
    # cur.execute(f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}' ")
    cur.execute(f"""
        SELECT max(crop_name) as payment_for, max(client_id) as sender_id,sum(amount_saved_daily) as amount_sent, max(payment_transactions.saving_target),
        max(payment_transactions.org_name) as org_name, max(partnership.price_per_kg) as price_per_kg
        FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.partnership ON payment_for = item_id
        RIGHT JOIN habahaba_trial.materials ON payment_for = material_id
         WHERE sender_id = {session['user_id']}  GROUP BY payment_for, crop_name
    """)
    user_items = cur.fetchall()
    print(user_items)
    cur.close()

    if request.method == 'POST':
        # client details
        client_id = request.form['client_id']
        client_name = request.form['client_name']
        client_phone = request.form['client_phone']
        amount = request.form['amount_added']

        # date and time details
        today = date.today()
        right_now = datetime.now()
        now = right_now.strftime("%H:%M:%S")

        try:
            balance = int(amount) + int(current_balance['balance'])

            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.wallet (client_id, client_name, client_phone, amount_sent,"
                        " balance, date_sent, time_sent, date_time) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (
                            client_id, client_name, client_phone, amount, balance, today, now, right_now
                        ))
            mysql.connection.commit()
            cur.close()
            flash('Amount added successfully', 'green lighten-2')
            return redirect(url_for('ukulima'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            balance = int(amount)

            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.wallet (client_id, client_name, client_phone, amount_sent,"
                        " balance, date_sent, time_sent, date_time) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (
                            client_id, client_name, client_phone, amount, balance, today, now, right_now
                        ))
            mysql.connection.commit()
            cur.close()
            flash('Amount added successfully', 'green lighten-2')
            return redirect(url_for('ukulima'))
    return render_template('ukulima.html', current_balance=current_balance, user_items=user_items)


@app.route('/ukulima-help/', methods=['POST', 'GET'])
@is_user_logged_in
def ukulima_help():
    if request.method == 'POST':
        client_id = session['user_id']
        username = request.form['username']
        phone_no = request.form['phone_no']
        category = request.form.get('category')
        more_info = request.form['more_info']

        try:
            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.error_reports (client_id, client_name, client_phone, category, more_info) 
            VALUES (%s, %s, %s, %s, %s)
            """, (
                client_id, username, phone_no, category, more_info
            ))
            mysql.connection.commit()
            cur.close()
            flash('Message sent successfully', 'green lighten-2')
            return redirect(url_for('ukulima'))
        except(MySQLdb.Warning, MySQLdb.Error) as e:
            action_performed = 'Tried to send message from help'
            action_time = datetime.utcnow()
            success = 0

            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.audit_report (sender_id, action_performed, action_time, success, additional_details) 
            VALUES(%s, %s, %s, %s, %s)
            """, (
                client_id, action_performed, action_time, success, e
            ))
            mysql.connection.commit()
            cur.close()

            flash('System busy, please try again later.', 'red lighten-2')
            return redirect(url_for('ukulima'))
    return render_template('ukulima_help.html')


@app.route('/login/')
def index():
    return render_template('login.html')


@app.route('/ukulima-targets/', methods=['POST', 'GET'])
@is_user_logged_in
def targets():
    cur = mysql.connection.cursor()
    cur.execute("SELECT distinct vendor_name FROM habahaba_trial.materials")
    vendors = cur.fetchall()
    cur.close()

    # list of all potential partners
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials")
    all_members = cur.fetchall()
    cur.close()

    members_json = json.dumps(all_members)

    cur = mysql.connection.cursor()
    # cur.execute(
    #     f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}' ORDER BY payment_id DESC ")
    cur.execute(f"""
            SELECT max(crop_name) as payment_for, sum(amount_saved_daily) as amount_sent, max(payment_transactions.saving_target) as saving_target, 
            max(payment_transactions.org_name) as org_name, max(partnership.price_per_kg) as price_per_kg
            FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.partnership ON payment_for = item_id 
            RIGHT JOIN habahaba_trial.materials ON payment_for = material_id
             WHERE sender_id = {session['user_id']}  GROUP BY payment_for
            """)
    partners = cur.fetchall()
    cur.close()

    # cur = mysql.connection.cursor()
    # cur.execute(f"SELECT * FROM habahaba_trial.partnership WHERE client_id = '{session['user_id']}'")
    # partnership_id = cur.fetchall()
    # cur.close()

    this_month = datetime.now().month
    this_year = datetime.now().year
    return render_template('ukulima_targets.html', vendors=vendors, all_members=all_members, partners=partners
                           # members_json=members_json
                           )


@app.route('/partner-details/', methods=['POST', 'GET'])
@is_user_logged_in
def partner_details():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials")
    vendor_materials = cur.fetchall()
    return json.dumps(vendor_materials)


@app.route('/remove-partner/<string:id_data>', methods=['POST', 'GET'])
@is_user_logged_in
def remove_partner(id_data):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM habahaba_trial.partnership WHERE partnership_id=%s" % id_data)
    mysql.connection.commit()
    cur.close()
    flash('Partner removed successfully', 'green lighten-2')
    return redirect(url_for('targets'))


@app.route('/partner-options/', methods=['POST', 'GET'])
@is_user_logged_in
def partner_options():
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM habahaba_trial.materials')
    partners = cur.fetchall()
    cur.close()
    return json.dumps(partners)


@app.route('/ukulima-target/', methods=['POST', 'GET'])
@is_user_logged_in
def ukulima_target():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials ORDER BY material_id ")
    vendor_materials = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.category ORDER BY category_id")
    categories = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.partners WHERE client_name = '{session['f_name']} {session['l_name']}'")
    partners = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT vendor_name, vendor_email, crop_name, materials.payment_method, materials.acc_number, "
        "materials.phone_no, price_per_kg FROM habahaba_trial.materials INNER JOIN "
        "habahaba_trial.vendors ON vendors.vendor_id=materials.vendor_id")
    results = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        # get partner
        partner = request.form.get('partner')
        partner_name = str(partner)

        cur = mysql.connection.cursor()
        cur.execute(f"SELECT * FROM habahaba_trial.materials WHERE vendor_name = '{partner_name}'")
        partner_goods = cur.fetchall()
        cur.close()
        redirect(url_for('ukulima_target', partner_goods=partner_goods))
    return render_template('ukulima_target.html', vendor_materials=vendor_materials, categories=categories,
                           partners=partners, results=results)


@app.route('/my-profile/', methods=['POST', 'GET'])
@is_user_logged_in
def ukulima_profile():
    return jsonify({"crops": ["maize", "beans"]})


@app.route('/testing/', methods=['POST', 'GET'])
@is_user_logged_in
def testing():
    vender_id = request.form.get('profile')

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT vendor_name, vendor_email, crop_name, materials.payment_method, materials.acc_number, "
        "materials.phone_no, price_per_kg FROM habahaba_trial.materials INNER JOIN "
        "habahaba_trial.vendors ON vendors.vendor_id=materials.vendor_id")
    results = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials ORDER BY material_id ")
    test_json = cur.fetchall()
    cur.close()
    json_var = f"{json.dumps(test_json)}"
    return json.dumps(results)


@app.route('/ukulima-offers/', methods=['POST', 'GET'])
@is_user_logged_in
def ukulima_offers():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.offers WHERE offer_status = 'Accepted'")
    available_offers = cur.fetchall()
    cur.close()

    var = mysql.connection.cursor()
    var.execute("SELECT count(*) FROM habahaba_trial.offers WHERE offer_status = 'accepted'")
    total_rows = var.fetchall()
    var.close()
    return render_template('ukulima_offers.html', available_offers=available_offers, total_rows=total_rows)


@app.route('/ukulima-offers-redirect/', methods=['POST', 'GET'])
@is_user_logged_in
def ukulima_offers_redirect():
    if request.method == 'POST':
        offer_id = request.form['offer_id']
        user_id = request.form['user_id']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.redirecting_table (client_id, offer_id) VALUES (%s, %s)", (
            user_id, offer_id
        ))
        mysql.connection.commit()
        cur.close()
    return redirect(url_for('specific_offer'))


@app.route('/selected-offer-json/', methods=['GET'])
@is_user_logged_in
def selected_offer_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT offer_id FROM habahaba_trial.redirecting_table WHERE client_id = '{session['user_id']}' ORDER BY redirect_id DESC")
    offer_id = cur.fetchone()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT material_id, materials.vendor_id, materials.vendor_name, materials.org_name, quantity_per_acre, price_per_kg,
     offer_name, percentage_off, region_available, valid_until, offer_id FROM habahaba_trial.materials 
    LEFT JOIN habahaba_trial.offers ON  materials.vendor_id = offers.vendor_id WHERE offer_id = {offer_id['offer_id']}
    """)
    offer = cur.fetchone()
    cur.close()
    return json.dumps(offer)


@app.route('/selected-offer/', methods=['POST', 'GET'])
@is_user_logged_in
def specific_offer():
    today = date.today()

    if request.method == 'POST':
        material_id = request.form['material_id']
        client_id = request.form['client_id']
        client_name = request.form['client_name']
        vendor_id = request.form['vendor_id']
        vendor_name = request.form['vendor_name']
        org_name = request.form['org_name']
        valid_until = request.form['valid_until']
        offer_id = request.form['offer_id']

        saving_duration = request.form['saving_duration']
        size_of_land = request.form['size_of_land']
        item_name = request.form['item_name']
        percentage_off = request.form['percentage_off']
        price_per_kg = request.form['price_per_kg']
        quantity_per_acre = request.form['quantity_per_acre']
        available_regions = request.form['available_regions']
        amount_to_pay = request.form['amount_to_pay']

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO habahaba_trial.picked_offer (offer_id, material_id, client_id, client_name, vendor_id, "
            "vendor_org, item_name, price_per_kg, quantity_per_acer, valid_until, save_until, "
            "available_regions, discount) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                offer_id, material_id, client_id, client_name, vendor_id, org_name, item_name, price_per_kg,
                quantity_per_acre, valid_until, saving_duration, available_regions, percentage_off
            ))
        mysql.connection.commit()
        cur.close()

        flash("Picked offer successfully", "green lighten-2")
        return redirect(url_for('specific_offer'))
    return render_template('selected_offer.html', current_date=today)


@app.route('/partners-json/', methods=['GET'])
@is_user_logged_in
def partners_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT distinct org_name, vendor_id FROM habahaba_trial.materials")
    partner = cur.fetchall()
    cur.close()
    return json.dumps(partner)


@app.route('/crops-json/', methods=['GET'])
@is_user_logged_in
def crops_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT MAX(material_id) as material_id, MAX(crop_name) as crop_name, MAX(offer_name) as offer_name,"
        " MAX(offers.offer_status) as offer_status, MAX(material_ids) as material_ids, MAX(offer_id) as offer_id,"
        " MAX(offer_name) as offer_name, MAX(region_available) as region_available, MAX(offers.offer_status) as offer_status FROM habahaba_trial.materials LEFT JOIN habahaba_trial.offers "
        "ON material_id = material_ids WHERE materials.material_status = 'accepted' GROUP BY crop_name ORDER BY material_id DESC")
    crops = cur.fetchall()
    cur.close()
    return json.dumps(crops)


@app.route('/ukulima-partners-offers-json/', methods=['GET'])
def ukulima_partners_offers_json():
    cur = mysql.connection.cursor()
    cur.execute(f""" 
    SELECT offer_id, offer_name, campaign_name, offer_status FROM habahaba_trial.offers
    WHERE offer_status = 'Accepted'
    """)
    offers = cur.fetchall()
    cur.close()
    return json.dumps(offers)


@app.route('/get-materials-json/', methods=['GET'])
@is_vendor_logged_in
def get_material_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT material_id, crop_name FROM habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}'")
    materials = cur.fetchall()
    cur.close()
    return json.dumps(materials)


@app.route('/crops-redirect/', methods=['POST'])
@is_user_logged_in
def crops_redirect():
    if request.method == 'POST':
        material_id = request.form['material_id']
        crop_name = request.form['crop_name']

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO habahaba_trial.redirecting_table (material_id, item_name, client_id) VALUES(%s, %s, %s)",
            (
                material_id, crop_name, session['user_id']
            ))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('vendor_goods'))


@app.route('/offers-redirect/', methods=['POST'])
@is_user_logged_in
def offers_redirect():
    if request.method == 'POST':
        material_id = request.form['offer_id']
        # crop_name = request.form['crop_name']

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO habahaba_trial.redirecting_table (offer_id, client_id) VALUES(%s, %s)",
            (
                material_id, session['user_id']
            ))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('vendor_goods'))


@app.route('/redirected-item/', methods=['GET'])
@is_user_logged_in
def redirected_item():
    # try:
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT material_id FROM habahaba_trial.redirecting_table WHERE client_id = '{session['user_id']}' 
    ORDER BY redirect_id DESC
    """)
    material_id = cur.fetchone()
    cur.close()
    # except:
    #     return redirect(url_for(''))

    cur = mysql.connection.cursor()
    cur.execute(f"""
        SELECT material_id, org_name, crop_name, quantity_per_acre, price_per_kg FROM habahaba_trial.materials
        WHERE material_id = {material_id['material_id']}
        """)
    item = cur.fetchall()
    cur.close()

    # checking if the item is an offer or item
    # if material_id['material_id'] !>
    return json.dumps(item)


@app.route('/vendor-goods-offers-json/', methods=['GET'])
@is_user_logged_in
def vendor_goods_offer_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
        SELECT material_id FROM habahaba_trial.redirecting_table WHERE client_id = '{session['user_id']}' 
        ORDER BY redirect_id DESC
        """)
    material_id = cur.fetchone()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT offer_id, offer_name, campaign_name, ((price_per_kg * offers.percentage_off) / 100), quantity_per_acre FROM habahaba_trial.materials 
    RIGHT JOIN habahaba_trial.offers ON material_ids = material_id WHERE material_id= '{material_id['material_id']}'
    AND offers.offer_status = 'Accepted'
    """)
    offers = cur.fetchall()
    cur.close()
    return json.dumps(offers)


@app.route('/selected-items-json/', methods=['GET'])
def selected_items():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(payment_transactions.org_name) as org_name, max(material_id) as material_id, max(crop_name) as crop_name
    FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.materials
    ON payment_for=material_id WHERE sender_id= '{session['user_id']}' AND amount_sent < saving_target GROUP BY material_id
    """)
    stuff = cur.fetchall()
    cur.close()
    return json.dumps(stuff)


@app.route('/ukulima-partners/', methods=['POST', 'GET'])
@is_user_logged_in
def ukulima_partners():
    cur = mysql.connection.cursor()
    cur.execute("SELECT distinct org_name FROM habahaba_trial.materials")
    vendor_materials = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials ORDER BY material_id ")
    test_json = cur.fetchall()
    cur.close()
    json_var = f"json: {json.dumps(test_json)}"

    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT vendor_org, material_id, crop_name  FROM habahaba_trial.partnership "
        f"RIGHT JOIN habahaba_trial.materials on item_id=material_id "
        f" WHERE partnership.client_id = '{session['user_id']}' ORDER BY partnership_id DESC ")
    partnered_vendors = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(payment_transactions.org_name) as vendor_org, max(material_id), max(crop_name) FROM habahaba_trial.payment_transactions 
    RIGHT JOIN habahaba_trial.materials ON material_id=item_purchased WHERE sender_id = '{session['user_id']}' GROUP BY material_id 
    """)
    stuff = cur.fetchall()
    cur.close()

    # offers
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.offers WHERE offer_status = 'accepted' ")
    vendor_offer = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        # material_id = request.form['material_id']
        client_id = request.form['client_id']
        client_name = request.form['client_name']
        vendor_org = request.form['vendor_org']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.redirecting_table (client_id, client_name, vendor_org)"
                    " VALUES ( %s, %s, %s)", (
                        client_id, client_name, vendor_org
                    ))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('vendor_goods'))
    return render_template('ukulima_partners.html', vendor_materials=vendor_materials, json_var=json_var,
                           partnered_vendors=partnered_vendors, vendor_offer=vendor_offer)


@app.route('/vendor-goods/', methods=['POST', 'GET'])
@is_user_logged_in
def vendor_goods():
    cur = mysql.connection.cursor()
    cur.execute("SELECT vendor_org FROM habahaba_trial.redirecting_table ORDER BY redirect_id DESC")
    vendor_org = cur.fetchone()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.materials WHERE org_name = '{vendor_org['vendor_org']}'")
    vendors = cur.fetchall()
    cur.close()
    return render_template('vendor_goods.html', vendors=vendors, vendor_org=vendor_org)


# all goods from JSON
@app.route('/all_goods/', methods=['POST', 'GET'])
@is_user_logged_in
def all_goods():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials")
    goods = cur.fetchall()
    cur.close()
    return json.dumps(goods)


@app.route('/selected-partner-redirect/', methods=['POST', 'GET'])
@is_user_logged_in
def selected_partner_redirect():
    if request.method == 'POST':
        user_id = session['user_id']
        material_id = request.form['material_id']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.selected_partner_redirect (user_id, material_id) "
                    "VALUES (%s, %s)", (user_id, material_id))
        mysql.connection.commit()
        cur.close()
    return redirect(url_for('selected_partner'))


@app.route('/testing-route/', methods=['GET'])
@is_user_logged_in
def testing_route():
    cur = mysql.connection.cursor()
    cur.execute("SELECT material_id FROM habahaba_trial.selected_partner_redirect ORDER BY redirect2_id DESC")
    client = cur.fetchone()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"SELECT quantity_per_acre, price_per_kg, materials.org_name, crop_name FROM habahaba_trial.materials "
                f"INNER JOIN habahaba_trial.vendors ON materials.vendor_id = vendors.vendor_id "
                f"WHERE material_id = '{client['material_id']}'")
    vendor_details = cur.fetchone()
    cur.close()
    return json.dumps(vendor_details)


# sends the selected vendor's material id to be opened in another page
@app.route('/selected-partner/', methods=['POST', 'GET'])
@is_user_logged_in
def selected_partner():
    cur = mysql.connection.cursor()
    cur.execute("SELECT material_id FROM habahaba_trial.selected_partner_redirect ORDER BY redirect2_id DESC")
    client = cur.fetchone()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.materials "
                f"RIGHT JOIN habahaba_trial.vendors ON materials.vendor_id = vendors.vendor_id "
                f"WHERE material_id = '{client['material_id']}'")
    vendor_details = cur.fetchone()
    cur.close()

    this_month = datetime.now().month
    this_year = datetime.now().year

    if request.method == 'POST':
        # vendor details
        item_id = request.form['item_id']
        vendor_id = request.form['vendor_id']
        crop_name = request.form['crop_name']
        vendor_org = request.form['vendor_org']
        save_until = request.form['save_until']
        category = request.form['category']
        material_id = request.form['material_id']

        price_per_kg = request.form['price_per_kg']
        quantity_per_acre = request.form['quantity_per_acre']

        # client details
        client_id = request.form['client_id']
        saving_target = request.form['payment_required']
        amount = 0

        cur = mysql.connection.cursor()
        cur.execute(f"""
        SELECT category_id FROM habahaba_trial.category WHERE category.category_name = {category}
        """)
        cat_id = cur.fetchone()
        category_id = cat_id['category_id']
        cur.close()

        counter_column = f"{vendor_id} {client_id} {crop_name} {this_month} {this_year}"
        client_vendor_crop = f"{vendor_id} {client_id} {crop_name}"

        # time the user sends the money
        today = date.today()
        right_now = datetime.now()
        now = right_now.strftime("%H:%M:%S")
        try:
            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.partnership(item_id, vendor_id, vendor_org, category, client_id, saving_target,
             save_until, price_per_kg, quantity_per_acre, category_id) VALUES(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                item_id, vendor_id, vendor_org, category, client_id, saving_target, save_until, price_per_kg,
                quantity_per_acre, category_id
            ))
            mysql.connection.commit()
            cur.close()

            month_no = datetime.now().month
            year = datetime.now().year
            date_counter = f"{month_no} {year}"

            amount_redeemed = 0
            quantity_redeemed = 0
            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.payment_transactions (vendor_id, org_name, sender_id, amount_sent, date_and_time,
             saving_target, payment_for, category, date_counter, amount_saved_daily, amount_redeemed, quantity_redeemed) 
             VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) 
            """, (
                vendor_id, vendor_org, client_id, amount, right_now, saving_target, material_id, category, date_counter,
                amount, amount_redeemed, quantity_redeemed
            ))
            mysql.connection.commit()
            cur.close()

            flash(f'{crop_name} Partner selected', 'green lighten-2')
            return redirect(url_for('ukulima_partners'))

        except(MySQLdb.Error, MySQLdb.Warning) as e:
            flash(f'You have already selected {vendor_org} for {crop_name}. Please select another item ',
                  'red lighten-2')
            return redirect(url_for('ukulima_partners'))

        # return redirect(url_for('ukulima_partners'))
    return render_template('selected_partner_onboard.html', vendor_details=vendor_details, client=client)


@app.route('/ukulima-deposits-json/', methods=['GET'])
def ukulima_deposits_json():
    # amount deposited
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT org_name, amount_sent, date(date_and_time) as date_sent, payment_for, (category) as cat, amount_saved_daily"
        f" FROM habahaba_trial.payment_transactions WHERE sender_id = '{session['user_id']}' ")
    deposits = cur.fetchall()
    cur.close()
    return json.dumps(deposits)


@app.route('/ukulima-redeemed-json/', methods=['GET'])
def ukulima_redeemed_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
        SELECT vendor_org, payment_for, amount_redeemed, date(date_redeemed) as date_redeemed, redemption_location, quantity_redeemed, (category) as cat 
        FROM habahaba_trial.redemption WHERE client_id = '{session['user_id']}'
        """)
    redeemed = cur.fetchall()
    cur.close()
    return json.dumps(redeemed)


@app.route('/ukulima-transactions/', methods=['GET'])
@is_user_logged_in
def ukulima_transactions():
    # amount deposited
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.payment_transactions WHERE sender_id = '{session['user_id']}' ")
    transactions = cur.fetchall()
    cur.close()
    return render_template('ukulima_transactions.html', transactions=transactions)


@app.route('/redemption-summary-json/', methods=['POST', 'GET'])
@is_vendor_logged_in
def redemption_summary_json():
    cur = mysql.connection.cursor()
    # cur.execute(f"SELECT payment_id, sender_name, amount_sent, saving_target, amount_redeemed, redemption_date "
    #             f"FROM habahaba_trial.payments_table WHERE vendor_id = '{session['vendor_id']}'")
    # cur.execute(f"""
    #     SELECT distinct redemption_id, concat_ws(' ', f_name, l_name) as farmer_name, crop_name, (redemption.category) as category,
    #     saving_target, amount_redeemed, quantity_redeemed, date_redeemed
    #     FROM habahaba_trial.redemption RIGHT JOIN habahaba_trial.partnership ON item_id = payment_for AND
    #     redemption.vendor_id = partnership.vendor_id AND redemption.client_id = partnership.client_id
    #     RIGHT JOIN habahaba_trial.users ON redemption.client_id = user_id RIGHT JOIN habahaba_trial.materials
    #     ON payment_for = material_id WHERE redemption.vendor_id = {session['vendor_id']} AND redemption.category != 'null'
    #     """)
    cur.execute(f"""
    SELECT distinct redemption_id, concat_ws(' ', f_name, l_name) as farmer_name, crop_name, (redemption.category) as category,
    saving_target, redemption.amount_redeemed, redemption.quantity_redeemed, date_redeemed FROM habahaba_trial.redemption
    RIGHT JOIN habahaba_trial.users ON client_id=user_id
    RIGHT JOIN habahaba_trial.materials ON payment_for=material_id
    RIGHT JOIN habahaba_trial.payment_transactions ON redemption.payment_for=payment_transactions.payment_for AND 
    redemption.vendor_id=payment_transactions.vendor_id WHERE redemption.vendor_id = {session['vendor_id']} AND redemption_id != 'null'
    """)
    redemption_summary = cur.fetchall()
    cur.close()
    return datatable(redemption_summary)


@app.route('/redemption-summary-test-json/', methods=['POST', 'GET'])
@is_vendor_logged_in
def redemption_summary_test_json():
    cur = mysql.connection.cursor()
    # cur.execute(f"""
    # SELECT redemption_id, concat_ws(' ', f_name, l_name), redemption.amount_redeemed, date_redeemed FROM habahaba_trial.redemption
    # RIGHT JOIN habahaba_trial.users ON client_id=user_id RIGHT JOIN habahaba_trial.payment_transactions ON redemption.vendor_id = redemption.vendor_id
    # """)
    cur.execute(f"""
    SELECT distinct redemption_id, concat_ws(' ', f_name, l_name) as farmer_name, crop_name, (redemption.category) as category,
    saving_target, amount_redeemed, quantity_redeemed, date_redeemed
    FROM habahaba_trial.redemption RIGHT JOIN habahaba_trial.partnership ON item_id = payment_for AND 
    redemption.vendor_id = partnership.vendor_id AND redemption.client_id = partnership.client_id 
    RIGHT JOIN habahaba_trial.users ON redemption.client_id = user_id RIGHT JOIN habahaba_trial.materials 
    ON payment_for = material_id WHERE redemption.vendor_id = {session['vendor_id']} AND redemption.category != 'null'
    """)
    redemption_summary = cur.fetchall()
    cur.close()
    return json.dumps(redemption_summary)


@app.route('/redemption-summary/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_redemption_summary():
    return render_template('v_redemption_summary.html')


@app.route('/savings-achievement-summary-json/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_savings_vs_achievement_summary_json():
    cur = mysql.connection.cursor()
    # cur.execute(f"""SELECT max(category), max(category) as category,count(*), sum(amount_sent),
    # format(sum(amount_sent)/ sum(saving_target) * 100, 2) as achievment_rate
    #  FROM habahaba_trial.payments_table WHERE vendor_id = {session['vendor_id']} GROUP BY category""")

    cur.execute(f"""
    SELECT max(category) as categoty, max(category) as categoty, count(distinct sender_id), sum(amount_saved_daily) as amount_saved,
    format(sum(amount_saved_daily) / sum(saving_target) * 100, 2) as achievment_rate 
    FROM habahaba_trial.payment_transactions WHERE vendor_id= '{session['vendor_id']}' AND transaction_status = 1 GROUP BY category
    """)
    savings_vs_achievement = cur.fetchall()
    cur.close()
    return datatable(savings_vs_achievement)


@app.route('/savings-achievement-summary-test-json/', methods=['GET'])
@is_vendor_logged_in
def v_savings_vs_achievement_summary_test_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(category) as categoty, max(category) as categoty, count(*), sum(amount_saved_daily) as amount_saved,
    format(sum(amount_saved_daily) / sum(saving_target) * 100, 2) as achievment_rate 
    FROM habahaba_trial.payment_transactions WHERE vendor_id= '{session['vendor_id']}' GROUP BY category
    """)
    savings_vs_target = cur.fetchall()
    cur.close()
    return json.dumps(savings_vs_target)


@app.route('/savings-achievement-summary/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_savings_vs_achievement_summary():
    return render_template('v_savings_vs_achievment.html')


@app.route('/saving-insight-json/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_saving_insight_json():
    cur = mysql.connection.cursor()
    # cur.execute(f"""
    # SELECT max(category), max(category), sum(amount_sent),
    # format(avg(saving_target / (price_per_kg * payments_table.quantity_per_acre)), 2)
    # FROM habahaba_trial.payments_table WHERE vendor_id = '{session['vendor_id']}' GROUP BY category
    # """)
    # vendor_savings_insight = cur.fetchall()

    cur.execute(f"""
        SELECT max(category_id) as category_id, max(materials.category) as category, sum(amount_saved_daily) as amount_saved,
        format(avg(saving_target / (price_per_kg * materials.quantity_per_acre)), 2) FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.materials
         ON payment_for = material_id WHERE payment_transactions.vendor_id = '{session['vendor_id']}' AND transaction_status = 1
        """)
    vendor_savings_insight = cur.fetchall()
    cur.close()
    return datatable(vendor_savings_insight)


# @app.route('/saving-insight-test/', methods=['GET'])
# def saving_insight_test():
#     cur = mysql.connection.cursor()
#     cur.execute(f"""
#     SELECT max(category_id) as category_id, max(materials.category) as category, sum(amount_saved_daily) as amount_saved,
#     format(avg(saving_target / (price_per_kg * materials.quantity_per_acre)), 2) FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.materials
#      ON payment_for = material_id WHERE payment_transactions.vendor_id = '{session['vendor_id']}'
#     """)
#     vendor_savings_insight = cur.fetchall()
#     cur.close()
#     return json.dumps(vendor_savings_insight)


@app.route('/savings-insight/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_savings_insight():
    return render_template('v_saving_insight.html')


@app.route('/saving-report-json/', methods=['GET'])
@is_vendor_logged_in
def saving_report_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT max(transaction_id) as transaction_id, max(concat_ws(' ', f_name, l_name)) as sender_name,"
        f" sum(amount_saved_daily) as amount_saved, max(saving_target), max(payment_transactions.category) as category, max(crop_name) as payment_for  "
        f"FROM habahaba_trial.payment_transactions "
        f" RIGHT JOIN habahaba_trial.users ON sender_id=user_id "
        f"RIGHT JOIN habahaba_trial.materials ON payment_for = material_id "
        f"WHERE  payment_transactions.vendor_id = {session['vendor_id']} AND transaction_status = 1 "
        f"GROUP BY payment_for, sender_name ")
    savings = cur.fetchall()
    cur.close()
    return datatable(savings)


@app.route('/saving-report/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_savings_report():
    return render_template('v_saving_report.html')


@app.route('/savings-summary-json/', methods=['GET'])
@is_vendor_logged_in
def v_savings_summary_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(transaction_id) as transaction_id, max(CONCAT_WS(' ', users.f_name, users.l_name)) as sender_name, max(crop_name) as crop_name,
     max(saving_target) as saving_target, sum(amount_saved_daily) as amount_sent, sum(amount_saved_daily) as amount_sent
       FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.vendors 
    ON payment_transactions.vendor_id = vendors.vendor_id RIGHT JOIN habahaba_trial.users ON 
    sender_id = user_id RIGHT JOIN habahaba_trial.materials ON payment_for = material_id WHERE
     payment_transactions.vendor_id = '{session['vendor_id']}' GROUP BY payment_for
    """)
    saving_summary = cur.fetchall()
    cur.close()
    return datatable(saving_summary)


@app.route('/savings-summary/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_savings_summary():
    return render_template('v_saving_summary.html')


@app.route('/campaign-performance-json/', methods=['GET'])
def campaign_performance_json():
    return


@app.route('/v_campaign_performance-json/', methods=['GET'])
@is_vendor_logged_in
def v_campaign_performance_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""SELECT max(campaign_name), max(campaign_name) as campaign_name, max(item_name) as item_name,
    max(discount) as discount, count(*) FROM habahaba_trial.picked_offer WHERE vendor_id = '{session['vendor_id']}'
     GROUP BY campaign_name""")
    offers = cur.fetchall()
    cur.close()
    return datatable(offers)


@app.route('/campaign-performance/', methods=['GET'])
@is_vendor_logged_in
def v_campaign_performance():
    return render_template('v_campaign_performance.html')


@app.route('/commissions-report/', methods=['GET'])
@is_vendor_logged_in
def v_commission_report():
    return render_template('v_commission_report.html')


@app.route('/commissions-report-json/', methods=['GET'])
@is_vendor_logged_in
def v_commission_report_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(category), max(category), sum(vendor_amount), sum(commission) 
     FROM habahaba_trial.commission WHERE vendor_id = '{session['vendor_id']}' GROUP BY category
    """)
    commission = cur.fetchall()
    cur.close()
    return datatable(commission)


@app.route('/redeemable-items-json/', methods=['POST', 'GET'])
@is_user_logged_in
def redeemable_items_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(transaction_id) as transaction_id, max(payment_transactions.org_name) as org_name, max(payment_for) as payment_for,
     max(saving_target) as saving_target, max(sender_id) as sender_id, max(payment_transactions.vendor_id) as vendor_id,
     max(quantity_per_acre) as quantity_per_acre, max(price_per_kg) as price_per_kg, sum(amount_saved_daily) as amount_saved_daily,
     max(crop_name) as crop_name, sum(amount_redeemed) as amount_redeemed, sum(quantity_redeemed) as quantity_redeemed, 
     max(material_id) as material_id
      FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.materials ON payment_for=material_id 
      WHERE sender_id = '{session['user_id']}' GROUP BY payment_for
    """)
    redeemable_items = cur.fetchall()
    cur.close()
    return json.dumps(redeemable_items)


@app.route('/redeemable-quantities-json/', methods=['GET'])
@is_user_logged_in
def redeemable_quantities_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT sum(quantity_redeemed) as quantity_redeemed, sum(amount_redeemed) as amount_redeemed, 
    max(crop_name) as crop_name, max(payment_for) as payment_for FROM habahaba_trial.redemption RIGHT JOIN habahaba_trial.materials
     ON payment_for=material_id WHERE client_id='{session['user_id']}' GROUP BY payment_for
    """)
    quantities = cur.fetchall()
    cur.close()
    return json.dumps(quantities)


@app.route('/redemption/', methods=['POST', 'GET'])
@is_user_logged_in
def redemption():
    # time the user sends the money
    today = date.today()
    right_now = datetime.now()
    current_time = right_now.strftime("%H:%M:%S")

    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(crop_name) as crop_name FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.materials
     ON payment_for = material_id WHERE sender_id = '{session['user_id']}' GROUP BY crop_name 
    """)
    items = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        client_id = request.form['client_id']
        vendor_id = request.form['vendor_id']
        vendor_org = request.form['vendor_org']
        quantity_per_acre = request.form['quantity_per_acre']
        price_per_kg = request.form['price_per_kg']
        redeemable_quantity = request.form['redeemable_quantity']
        transaction_id = request.form['transaction_id']
        item_redeemed = request.form['item_redeemed']
        material_id = request.form['material_id']
        quantity_redeemed = request.form['quantity_redeemed']
        saving_target = request.form['saving_target']
        current_quantity_redeemed = request.form['quantity_to_redeem']

        current_amount_redeemed = round((float(current_quantity_redeemed) * float(price_per_kg)), 2)
        total_redeemable_quantity = round(((float(saving_target) / float(price_per_kg)) - float(quantity_redeemed)), 2)

        if (float(current_quantity_redeemed) + float(quantity_redeemed)) > total_redeemable_quantity:
            flash(f'You can only redeem a maximum of {total_redeemable_quantity} KGs / L', 'red lighten-2')
            return redirect(url_for('redemption'))
        else:
            time_redeemed = datetime.utcnow()

            cur = mysql.connection.cursor()

            try:
                cur.execute(f"""
                INSERT INTO habahaba_trial.redemption (vendor_id, vendor_org, client_id, payment_for, date_redeemed, 
                quantity_redeemed, amount_redeemed) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """, (
                    vendor_id, vendor_org, client_id, material_id, time_redeemed, current_quantity_redeemed,
                    current_amount_redeemed
                ))
                mysql.connection.commit()
                cur.close()

                flash('Item redeemed successfully', 'green lighten-2')
                return redirect(url_for('redemption'))

            except(MySQLdb.Warning, MySQLdb.Error) as e:
                action_performed = f'Failed to Redeem {item_redeemed}'
                success = 0
                action_time = datetime.utcnow()

                cur = mysql.connection.cursor()
                cur.execute(f"""
                INSERT INTO habahaba_trial.audit_report (sender_id, action_performed, action_time, success,
                 additional_details) VALUES (%s, %s, %s, %s, %s)
                """, (
                    client_id, action_performed, action_time, success, e
                ))
                mysql.connection.commit()
                cur.close()

                flash(f'Failed to redeem item', 'red lighten-2')
                return redirect(url_for('redemption'))
    return render_template('ukulima_redemption.html', items=items)


@app.route('/redemption-history-json/', methods=['GET'])
def redemption_history():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT vendor_org, payment_for, quantity_redeemed,date_redeemed, amount_redeemed,  category  
    FROM habahaba_trial.redemption
    """)
    history = cur.fetchall()
    cur.close()
    return datatable(history)


# @app.route('/client-crops-json/', methods=['GET'])
# def clients_crops():
#     cur = mysql.connection.cursor()
#     cur.execute(
#         f"SELECT sender_id, vendor_id, payment_for FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}'")
#     client_crops = cur.fetchall()
#     cur.close()
#     return json.dumps(client_crops)


@app.route('/ukulima-funds/', methods=['POST', 'GET'])
@is_user_logged_in
def ukulima_funds():
    # cur = mysql.connection.cursor()
    # cur.execute(
    #     f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id= '{session['user_id']}' ORDER BY payment_id DESC ")
    # partners = cur.fetchall()
    # cur.close()

    # cur = mysql.connection.cursor()
    # cur.execute(
    #     f"SELECT amount_sent FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}' "
    #     f"ORDER BY payment_id DESC ")
    # previous_value = cur.fetchone()
    # cur.close()

    # list of crops that a client is subscribed to
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT max(crop_name) as payment_for FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.materials"
        f" ON payment_for=material_id WHERE amount_sent < saving_target AND sender_id = '{session['user_id']}' GROUP BY crop_name")
    client_crops = cur.fetchall()
    cur.close()

    # time the user sends the money
    today = date.today()
    right_now = datetime.now()
    now = right_now.strftime("%H:%M:%S")
    this_month = datetime.now().month
    this_year = datetime.now().year

    if request.method == 'POST':
        # vendor details
        client_id = request.form['client_id']
        vendor_id = request.form['vendor_id']
        vendor_org = request.form['vendor_org']
        saving_target = request.form['saving_target']
        category = request.form['category']
        item_purchased = request.form['item_purchased']
        total_paid = request.form['total_paid']
        amount_saved = request.form['payment']
        material_id = request.form['material_id']
        client_phone = request.form['phone_number']

        transaction_status = 0

        date_counter = f"{this_month} {this_year}"

        if int(amount_saved) + int(total_paid) > int(saving_target):
            flash('The amount surpasses your target', 'orange lighten-2')
            return redirect(url_for('ukulima_funds'))
        else:
            try:
                amount_redeemed = 0
                quantity_redeemed = 0
                cur = mysql.connection.cursor()
                cur.execute(f"""
                INSERT INTO habahaba_trial.payment_transactions (sender_id, vendor_id, org_name, saving_target, category,
                 payment_for, amount_saved_daily, amount_redeemed, quantity_redeemed) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    client_id, vendor_id, vendor_org, saving_target, category, material_id, amount_saved,
                    amount_redeemed, quantity_redeemed
                ))
                mysql.connection.commit()
                cur.close()
                flash('Amount sent successfully', 'green lighten-2')
                return redirect(url_for('ukulima_funds'))

            except(MySQLdb.Error, MySQLdb.Warning) as e:
                flash(f'Payment failed {e}', 'red lighten-2')
                return redirect(url_for('ukulima_funds'))

        # flash(f'Amount sent successfully {vendor_crop}', 'green lighten-2 white-text')
        # return redirect(url_for('ukulima_funds'))
    # return render_template('ukulima_funds.html', partners=partners, client_crops=client_crops)
    return render_template('ukulima_funds.html', client_crops=client_crops)


@app.route('/waiting/', methods=['GET'])
def waiting_page():
    return render_template('waiting.html')


@app.route('/ukulima-funds-json/', methods=['GET'])
@is_user_logged_in
def ukulima_funds_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(client_id) as client_id, max(partnership.vendor_id) as vendor_id, max(vendor_org) as vendor_org,
     max(payment_transactions.saving_target) as saving_target, max(partnership.category) as item_category,
      max(crop_name) as crop_name, max(material_id) as material_id,sum(amount_saved_daily) as total_paid FROM habahaba_trial.partnership 
    RIGHT JOIN habahaba_trial.materials ON item_id=material_id RIGHT JOIN habahaba_trial.payment_transactions 
    ON material_id=payment_for WHERE client_id = '{session['user_id']}' GROUP BY payment_for, vendor_org, crop_name
    """)
    partners = cur.fetchall()
    cur.close()

    # cur = mysql.connection.cursor()
    # cur.execute(f"""
    # SELECT transaction_id, vendor_id, org_name,  FROM habahaba_trial.payment_transactions RIGHT JOIN habahaba_trial.materials ON payment_for=material_id
    # RIGHT JOIN habahaba_trial.vendors ON payment_transactions.vendor_id=vendors.vendor_id
    # """)

    return json.dumps(partners)


# @app.route('/funds-testing/', methods=['POST', 'GET'])
# @is_user_logged_in
# def funds_testing():
#     cur = mysql.connection.cursor()
#     cur.execute(
#         f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id= '{session['user_id']}' ORDER BY payment_id DESC ")
#     partners = cur.fetchall()
#     cur.close()
#     return json.dumps(partners)


@app.route('/get_offers', methods=['GET'])
@is_user_logged_in
def get_offers():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT vendor_name, vendor_email, org_name, offer_name, percentage_off, valid_until, region_available, "
        "offer_status"
        " FROM habahaba_trial.offers ORDER BY offer_id DESC ")
    all_offers = cur.fetchall()
    cur.close()
    empty_list = []
    # for row in all_offers:
    #     row_list = []
    #     for item in row:
    #         print(item)
    #         row_list.append(row[item])
    #     empty_list.append(row_list)
    # print(empty_list)
    # return jsonify({"crops": ["maize", "beans"]})
    for row in all_offers:
        row_list = []
        for item in row:
            row_list.append(row[item])
        empty_list.append(row_list)
    print(empty_list)
    return jsonify({"data": empty_list})


@app.route('/redemption-orders/', methods=['POST', 'GET'])
@is_user_logged_in
def redemption_orders():
    # date details
    today = date.today()
    right_now = datetime.now()
    now = right_now.strftime("%H:%M:%S")
    if request.method == 'POST':
        # client details
        client_id = request.form['client_id']
        client_name = request.form['client_name']
        client_email = request.form['client_email']
        client_phone = request.form['client_phone']
        # vendor details
        vendor_id = request.form['vendor_id']
        vendor_name = request.form['vendor_name']
        vendor_org = request.form['vendor_org']
        # payment details
        payment_for = request.form['payment_for']
        amount_paid = request.form['amount_paid']
        payment_id = request.form['payment_id']
        partnership_id = request.form['partnership_id']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.vendor_wallet(vendor_id, vendor_name, vendor_org, client_id, "
                    "client_name, client_email, client_phone, payment_for, amount_paid, "
                    "redemption_time, redemption_date) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                        vendor_id, vendor_name, vendor_org, client_id, client_name, client_email, client_phone,
                        payment_for, amount_paid, now, today
                    ))
        cur.execute(f"DELETE FROM habahaba_trial.payments_table WHERE payment_id = '{payment_id}'")
        cur.execute(f"DELETE FROM habahaba_trial.partnership WHERE partnership_id = '{partnership_id}'")
        mysql.connection.commit()
        cur.close()
        flash('Sent redemption request successfully', 'green lighten-2')
        return redirect(url_for('targets'))

    return render_template('vendor_redemption_offers.html')


@app.route('/test/', methods=['POST', 'GET'])
def test_route():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.vendors")
    all_materials = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        vendor_id = request.form['vendor_id']
        vendor_name = request.form['vendor_name']
        org_name = request.form['org_name']
        payment_method = request.form['payment_method']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.test_route(vendor_id, vendor_name, org_name, payment_method) "
                    "VALUES (%s, %s, %s, %s)",
                    (vendor_id, vendor_name, org_name, payment_method))
        mysql.connection.commit()
        cur.close()
    return render_template('test_route.html', all_materials=all_materials, values=json.dumps(all_materials))


@app.route('/test-chart/', methods=['POST', 'GET'])
def test_chart():
    cur = mysql.connection.cursor()
    # cur.execute("SELECT * FROM habahaba_trial.payment_transactions")
    cur.execute("DESCRIBE habahaba_trial.materials")
    transactions = cur.fetchall()
    cur.close()
    return render_template('test_chart.html', transactions=transactions)


@app.route('/testing-chart/', methods=['GET'])
def testing_chart():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT max(payment_for) as payment_for, sum(amount_sent) as amount_sent FROM habahaba_trial.payment_transactions "
        "GROUP BY payment_for ")
    transaction = cur.fetchall()
    cur.close()
    return json.dumps(transaction)


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[MPESA DARAJA API]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
consumer_key = 'jFno3vaGAHGSq9vdiYrAg68DCGZ3jeie'
consumer_secret = '2IqOGxgPUTL2BVbv'
# base_url = 'http://197.232.79.73:801'
base_url = 'http://habahaba.mzawadi.com'


def ac_token():
    mpesa_auth_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    data = (requests.get(mpesa_auth_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))).json()
    return data['access_token']


# methods=['POST', 'GET']
@app.route('/token/')
def tokens():
    data = ac_token()
    print(data)
    return data['access_token']


# register urls
@app.route('/register-url/', methods=['POST', 'GET'])
def register_url():
    mpesa_endpoint = 'https://sandbox.safaricom.co.ke/mpesa/c2b/v1/registerurl'
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {ac_token()}"
    }
    req_body = {
        "ShortCode": 600979,
        "ResponseType": "Completed",
        "ConfirmationURL": f"{base_url}/confirm/",
        "ValidationURL": f"{base_url}/validate/"
    }
    response_data = requests.post(
        mpesa_endpoint,
        json=req_body,
        headers=headers
    )

    # other_response = requests.request("POST", "https://sandbox.safaricom.co.ke/mpesa/c2b/v1/registerurl",
    #                                   headers=headers, data=req_body)
    # return other_response.text.encode('utf8')
    return response_data.json()


@app.route('/confirm/', methods=['POST', 'GET'])
def confirm():
    # get data
    data = request.get_json()
    # write data
    file = open('confirm.json', 'a')
    file.write(json.dumps(data))
    file.close()
    return {
        "ResultCode": 0,
        "ResultDesc": "Accepted"
    }


@app.route('/validate/', methods=['POST', 'GET'])
def validate():
    # get data
    data = request.get_json()
    # write data
    file = open('validate.json', 'a')
    file.write(json.dumps(data))
    file.close()
    print(file)
    return {
        "ResultCode": 0,
        "ThirdPartyTransID": 'Yay_my_server',
        "ResultDesc": "Accepted"
    }


# simulate transaction
@app.route('/simulate-transaction/', methods=['POST', 'GET'])
def simulate():
    mpesa_endpoint = 'https://sandbox.safaricom.co.ke/mpesa/c2b/v1/simulate'
    headers = {"Authorization": f"Bearer {ac_token()}"}
    request_body = {
        "ShortCode": "600999",
        "CommandID": "CustomerPayBillOnline",
        "BillRefNumber": "TestPay1",
        "Msisdn": "254705912645",
        "Amount": 1
    }
    simulate_response = requests.post(
        mpesa_endpoint,
        json=request_body,
        headers=headers
    )
    return simulate_response.json()


@app.route('/mpesa/', methods=['POST', 'GET'])
def mpesa():
    return render_template('daraja.html')


# amount, phone_number
@app.route('/pay/', methods=['POST', 'GET'])
def mpesa_express():
    # my_endpoint = "https://804b-197-232-79-73.in.ngrok.io/"
    my_endpoint = "http://habahaba.mzawadi.com"

    # phone_no_str = str(phone_number)
    # phone_no = phone_no_str.replace('0', '254', 1)

    endpoint = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
    access_token = ac_token()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {ac_token()}"
    }

    password = "MTc0Mzc5YmZiMjc5ZjlhYTliZGJjZjE1OGU5N2RkNzFhNDY3Y2QyZTBjODkzMDU5YjEwZjc4ZTZiNzJhZGExZWQyYzkxOTIwMjMwMTIyMTYxMTMy"
    password = base64.b64encode(password.encode('utf-8'))

    timestamps = datetime.now()
    times = timestamps.strftime("%Y%m%d%H%M%S")
    current_time = str(times)
    data = {
        "BusinessShortCode": 174379,
        "Password": "MTc0Mzc5YmZiMjc5ZjlhYTliZGJjZjE1OGU5N2RkNzFhNDY3Y2QyZTBjODkzMDU5YjEwZjc4ZTZiNzJhZGExZWQyYzkxOTIwMjMwMTI0MDkzMjE3",
        "Timestamp": "20230124093217",
        "TransactionType": "CustomerPayBillOnline",
        "Amount": 1,
        "PartyA": 254713562964,
        "PartyB": 174379,
        "PhoneNumber": 254713562964,
        "CallBackURL": my_endpoint + "/callback/",
        "AccountReference": "CompanyXLTD",
        "TransactionDesc": "Payment of X"
    }
    # print(data, headers)
    # this_data = json.dumps(data)
    res = requests.post(endpoint, json=data, headers=headers)
    my_res = requests.request("POST", "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
                              headers=headers, json=data)
    # flash('Success', 'grey lighten-2')
    print(times)
    # print(phone_no)
    # return res.json()
    return res.json()


@app.route('/validate-payment/', methods=['POST', 'GET'])
def validate_payment():
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {ac_token()}'
    }

    payload = {
        "Initiator": "testapi",
        "SecurityCredential": "aF10wp7OT0xH61Cl4dA2gqxDJp9hR+TFPXrpnazle0da6YnwlhAvb4IZoArwNumy1uLdJ7Yy1N3xlFWpixD6cK/ZucF5I4Jo7EyvMv01TP3tPj54wI1NWBFbssBu/HNVsJ7+Q8IjTa8vDFs0j97M8nUkm8TM8jY87Q/QefM2iDEnimOH7HTL2tVA3QHp5boQSnjN5/gtmsalebN0valeWDMyHaUu8ZHbqGL5Szt6Z2XFm3tYj19jS6huBnkquxa4vz4UWzX6UxjuoMR8PW8o6gp15gny2yoFWSCTq+5X5Y3xA9G1xos/Ke0OaH5W2THiE8/Q9NHFOu7KcuEOPO6nwA==",
        "CommandID": "TransactionStatusQuery",
        "TransactionID": "OEI2AK4Q16",
        "PartyA": 600997,
        "IdentifierType": "4",
        "ResultURL": "https://mydomain.com/TransactionStatus/result/",
        "QueueTimeOutURL": "https://mydomain.com/TransactionStatus/queue/",
        "Remarks": "Success",
        "Occasion": "Paid",
    }
    responses = requests.request(
        "POST",
        'https://sandbox.safaricom.co.ke/mpesa/transactionstatus/v1/query',
        headers=headers,
        data=payload
    )
    response_value = requests.post(
        'https://sandbox.safaricom.co.ke/mpesa/transactionstatus/v1/query',
        headers=headers,
        json=payload
    )
    response = responses.text.encode('utf-8')
    print(response)
    return jsonify({"value": 5})


# consume M-PESA Express Callback
@app.route('/callback/', methods=['GET'])
def incoming():
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {ac_token()}'

    }
    data = request.get_json()

    merchantid = data['Body']['stkCallback']['MerchantRequestID']
    checkoutid = data['Body']['stkCallback']['CheckoutRequestID']
    status = data['Body']['stkCallback']['ResultCode']
    if status == 0:
        payload = data['Body']['stkCallback']['CallbackMetadata']
        items = payload['Item']
        amount = 0
        mpesaref = ""
        transdate = ""
        phoneno = ""

        for item in items:
            match item['Name']:
                case "Amount":
                    amount = item['Value']
                case "MpesaReceiptNumber":
                    mpesaref = item['Value']
                case "PhoneNumber":
                    phoneno = item['Value']
                case "TransactionDate":
                    value = str(item['Value'])
                    # transdate =  value[0:4] +"-"+ value[4:6] +"-"+ value[6:8]
                    transdate = f'{value[0:4]}-{value[4:6]}-{value[6:8]} ' \
                                f'{value[8:10]}:{value[10:12]}:{value[12:14]}'

        print(amount, mpesaref, phoneno, transdate)
    return 'ok'


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[CSV]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
@app.route('/csv/', methods=['POST'])
def csv():
    if request.method == 'POST':
        names = request.files['names']
        # cur = mysql.connection.cursor()
        # for this_name in names:
        #     # print(this_name.rstrip())
        #     cur.execute("INSERT INTO habahaba_trial.names (f_names, gender) VALUES (%s, %s) ", (
        #         this_name[0:], this_name[0:]
        #     ))
        #     mysql.connection.commit()
        # cur.close()

        cur = mysql.connection.cursor()
        cur.execute("""LOAD DATA INFILE %s INTO TABLE habahaba_trial.users 
        FIELDS TERMINATED BY ',' LINES TERMINATED BY '\n'""", names)
        mysql.connection.commit()
        cur.close()

        flash("Sent successfully", "success")
    return redirect(url_for('admin_view_vendors'))


# SMS/TEXT
@app.route("/text/", methods=['POST'])
def text_msg(phone_no, password):
    # phone = request.form['phone']
    headers = {
        "Content-Type": "application/json"
        # "Authorization": f"Bearer {ac_token()}"
    }

    payload = {
        "apikey": "1d0bda2feac539bfb5042d00440a0877",
        "partnerID": 196,
        'pass_type': "plain",
        "shortcode": "MZAWADI",
        "mobile": phone_no,
        "message": f"Use the phone number {phone_no} and password {password} to login to http://habahaba.mzawadi.com/",
    }
    my_res = requests.request("POST", "https://quicksms.advantasms.com/api/services/sendsms/",
                              headers=headers, json=payload)

    return my_res.json()


# VENDOR TEXTS
@app.route("/vendor-text/", methods=['POST'])
def vendor_text_msg(phone_no, password):
    # phone = request.form['phone']
    headers = {
        "Content-Type": "application/json"
        # "Authorization": f"Bearer {ac_token()}"
    }

    payload = {
        "apikey": "1d0bda2feac539bfb5042d00440a0877",
        "partnerID": 196,
        'pass_type': "plain",
        "shortcode": "MZAWADI",
        "mobile": phone_no,
        "message": f"Use the phone number {phone_no} and password {password} to login to http://habahaba.mzawadi.com/vendor-login",
    }
    my_res = requests.request("POST", "https://quicksms.advantasms.com/api/services/sendsms/",
                              headers=headers, json=payload)

    return my_res.json()


# ADMIN TEXTS
@app.route("/admin-text/", methods=['POST'])
def admin_text_msg(phone_no, password):
    # phone = request.form['phone']
    headers = {
        "Content-Type": "application/json"
        # "Authorization": f"Bearer {ac_token()}"
    }

    payload = {
        "apikey": "1d0bda2feac539bfb5042d00440a0877",
        "partnerID": 196,
        'pass_type': "plain",
        "shortcode": "MZAWADI",
        "mobile": phone_no,
        "message": f"Use the phone number {phone_no} and password {password} to login to http://habahaba.mzawadi.com/admin-login",
    }
    my_res = requests.request("POST", "https://quicksms.advantasms.com/api/services/sendsms/",
                              headers=headers, json=payload)

    return my_res.json()


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')

# LEARN JWT
