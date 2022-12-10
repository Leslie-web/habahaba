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
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

from flask import *
from flask_mysqldb import MySQL

# from passlib.hash import sha256_crypt
from functools import wraps
from datetime import date, datetime, timedelta
# import datetime

from counties import counties

# ngrok
# from flask_ngrok import run_with_ngrok

app = Flask(__name__)
# run_with_ngrok(app)

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


# @app.before_request
# def check_url_exist():
#     if request.path not in app.url_map.iter_rules():
#         return render_template('vendor_page_not_found.html'), 404

# @app.before_request
# def check_url_exist():
#     for rule in app.url_map.iter_rules():
#         if request.path == rule.rule:
#             print(f'http://127.0.0.1:5000{rule}')
#
#             return redirect(f'http://127.0.0.1:5000{rule}')
#
#     return render_template('vendor_page_not_found.html'), 404


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
# @not_admin_logged_in
def admin_login():
    if request.method == 'POST':
        # email = request.form['email']
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

            # admin_var = 'admin_logged_in'

            if bcrypt.checkpw(password_candidate.encode('utf-8'), password.encode('utf-8')):
                # if sha256_crypt.verify(password_candidate, password):
                session['admin_logged_in'] = True
                session['admin_id'] = uid
                session['email'] = email
                session['f_name'] = f_name
                session['l_name'] = l_name
                session['phone_no'] = phone_no

                login_time = datetime.utcnow()
                message = f'{f_name} {l_name} logged in'
                success_status = 1

                cur = mysql.connection.cursor()
                cur.execute(f"""
                INSERT INTO habahaba_trial.audit_report (audit_report.admin_id, audit_report.action_performed, audit_report.action_time, audit_report.success) 
                VALUES (%s, %s, %s, %s)
                """, (
                    uid, message, login_time, success_status
                ))
                mysql.connection.commit()

                auth = request.application
                private_key = rsa.generate_private_key(
                    public_exponent=65537,
                    key_size=2048
                )
                public_key = private_key.public_key()

                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                public_pem = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                # print(public_pem)
                # print(private_pem)

                payload = {
                    'admin_id': data['admin_id'],
                    'f_name': f_name,
                    'l_name': l_name,
                    'phone_no': phone_no,
                    # 'exp': str(datetime.datetime.utcnow() + timedelta(seconds=120)),
                }
                # jwt_token = jwt.encode(payload, app.config['JWT_SECRET_KEY'], algorithm='HS256')
                # print(jwt_token)
                # return jwt.decode(jwt_token, algorithms='HS256')
                encoded = jwt.encode(
                    payload,
                    private_pem,
                    algorithm='RS256',
                )
                token = jwt.encode(payload, app.config['JWT_SECRET_KEY'])
                print(token)
                print(request.headers.get("Content-type"))

                # print(encoded)
                # print(jwt.decode(encoded, 'qwerty', algorithms='HS256'))
                # decoded = jwt.decode(encoded, public_pem, algorithms=['RS256'])

                # print(decoded)

                x = '1'

                cur.execute("UPDATE habahaba_trial.admin SET online=%s WHERE admin_id=%s", (x, uid))

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
        x = '0'
        cur.execute("UPDATE habahaba_trial.admin SET online=%s WHERE admin_id=%s ", (x, uid))
        session.clear()
        flash(f'You are now logged out {f_name}', 'danger')
        return redirect(url_for('admin_login'))
    return redirect(url_for('admin_login'))


# admin home page
@app.route('/admin-home/', methods=['POST', 'GET'])
@is_admin_logged_in
# @token_required
def alan_code():
    authorization_header = request.headers.get('Authorization')

    # if not authorization_header:
    #     return {'error', 'Authorization header is missing'}, 401
    # all users
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


@app.route('/categories-report/', methods=['GET'])
def a_categories_reports():
    cur = mysql.connection.cursor()
    cur.execute("SELECT category FROM habahaba_trial.payments_table")
    categories = cur.fetchall()
    cur.close()
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
            cur.close()
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            flash("Error setting up Vendor!", "warning")
        flash("Vendor has been set up successfully", "success")
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

            flash("Vendor added successfully. Please setup the vendor at Vendor Setup", "success")
            return redirect(url_for('vendor_onboarding'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            print(MySQLdb.Error(e))
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
    cur = mysql.connection.cursor()
    cur.execute("SELECT vendor_id, org_name, sender_id, sender_name, sender_phone, amount_sent, date_sent, "
                " saving_target, payment_for, amount_redeemed, quantity_redeemed "
                " FROM habahaba_trial.payment_transactions")
    transactions = cur.fetchall()
    cur.close()
    if request.method == 'POST':
        client_id = request.form['client_id']
        cur = mysql.connection.cursor
        return redirect(url_for('admin_individual_transactions'))
    return render_template('admin_transactions.html', transactions=transactions)


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
    SELECT client_name, client_name, vendor_org, category, amount_redeemed, DATE(date_redeemed), redemption_location
     FROM habahaba_trial.redemption
    """)
    redemptions_summary = cur.fetchall()
    cur.close()
    return datatable(redemptions_summary)


@app.route('/vendor-summary/', methods=['GET'])
@is_admin_logged_in
def a_vendor_summary():
    return render_template('a_vendor_summary.html')


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


@app.route('/farm-scale-json/', methods=['GET'])
@is_admin_logged_in
def a_farm_scale_json():
    cur = mysql.connection.cursor()
    cur.execute("""
    SELECT sender_name, (saving_target / (quantity_per_acre * payments_table.price_per_kg)),
     payment_for, payment_id FROM habahaba_trial.payments_table
    """)
    farm_scale = cur.fetchall()
    cur.close()
    return datatable(farm_scale)


@app.route('/crop-summary/', methods=['GET'])
@is_admin_logged_in
def a_crop_summary():
    return render_template('a_crop_summary.html')


@app.route('/crop-summary-json/', methods=['GET'])
@is_admin_logged_in
def a_crop_summary_json():
    cur = mysql.connection.cursor()
    cur.execute("""
    SELECT sender_name, payment_for, 
    format(saving_target / (quantity_per_acre * payments_table.price_per_kg), 2), org_name, org_name, payment_id
    FROM habahaba_trial.payments_table
    """)
    crop_summary = cur.fetchall()
    cur.close()
    return datatable(crop_summary)


@app.route('/saving-summary/', methods=['GET'])
@is_admin_logged_in
def a_saving_summary():
    return render_template('a_saving_summary.html')


@app.route('/saving-summary-json/', methods=['GET'])
@is_admin_logged_in
def a_saving_summary_json():
    cur = mysql.connection.cursor()
    cur.execute("""
    SELECT payment_id, sender_name, amount_sent, category FROM habahaba_trial.payments_table
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


@app.route('/vendor-insight-json/', methods=['GET'])
def a_vendor_insight_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""SELECT max(org_name), max(category), ((count(*) / avg(sender_id)) * 100), 
        format((sum(saving_target) / (sum(price_per_kg) * sum(quantity_per_acre))), 2)
        FROM habahaba_trial.payments_table GROUP BY category, org_name""")
    vendor_insight = cur.fetchall()
    cur.close()

    return datatable(vendor_insight)


@app.route('/vendor-summary-json/', methods=['GET'])
@is_admin_logged_in
def a_vendor_summary_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"""SELECT max(payments_table.org_name), max(category), sum(amount_sent) , max(date_registered)
        FROM habahaba_trial.payments_table INNER JOIN habahaba_trial.vendors ON payments_table.vendor_id = vendors.vendor_id
         group by category, payments_table.org_name""")
    vendor_summary = cur.fetchall()
    return datatable(vendor_summary)


@app.route('/float-summary-chart/', methods=['GET'])
def float_summary_chart():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT sum(quantity_redeemed) as quantity_redeemed, sum(amount_sent) as amount_sent ,"
        " sum(amount_redeemed) as amount_redeemed, sum(saving_target - payments_table.amount_redeemed) as balance "
        "FROM habahaba_trial.payments_table")
    summary_chart = cur.fetchall()
    cur.close()
    return json.dumps(summary_chart)


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
@app.route('/customer-summary-json/', methods=['POST', 'GET'])
@is_admin_logged_in
def customer_summary_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT payment_id, sender_name, location_of_land,
     format((payments_table.saving_target / (quantity_per_acre * payments_table.price_per_kg)), 2),
     format((payments_table.saving_target / (quantity_per_acre * payments_table.price_per_kg)), 2),
     org_name, category, amount_sent, format(((amount_sent / saving_target) * 100), 2) FROM habahaba_trial.payments_table 
    INNER JOIN habahaba_trial.users ON sender_id = user_id
    """)
    user_details = cur.fetchall()
    cur.close()
    return datatable(user_details)


@app.route('/vendor-reports-json/', methods=['POST', 'GET'])
@is_admin_logged_in
def admin_vendor_reports_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT vendor_id, vendor_name, org_name, sender_id, sender_name, amount_sent, saving_target,"
        " payment_for FROM habahaba_trial.payment_transactions")
    transactions = cur.fetchall()
    cur.close()
    return json.dumps(transactions)


@app.route('/admin-transactions-json/', methods=['GET'])
@is_admin_logged_in
def admin_transactions_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT max(sender_name), sender_phone, max(org_name), sum(amount_sent), max(sender_id),"
        " max(payment_for), max(transaction_id) FROM habahaba_trial.payment_transactions group by sender_phone")
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
    SELECT sender_name, sender_phone, vendor_name, amount_saved_daily 
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
        SELECT sender_name, sender_phone, vendor_name, amount_saved_daily 
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
    cur.execute(f"SELECT max(client_name) FROM habahaba_trial.partnership WHERE vendor_id = '{session['vendor_id']}' "
                f"GROUP BY client_name")
    users = cur.fetchall()
    cur.close()

    # products
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}'")
    products = cur.fetchall()
    cur.close()

    # offers
    # names = f"{session['f_name']} {session['l_name']}"
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

            flash("New account added successfully", "success")
            return redirect(url_for('vendor_add_account'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            flash("This phone number already exists, please enter another phone number", "warning")
    return render_template('vendor_add_account.html')


# VENDOR PRODUCT VERIFICATION
@app.route('/vendor-product-registration/', methods=['POST', 'GET'])
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
                        " region, material_status)"
                        " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                            vendor_id, vendor_name, vendor_email, item_name, quantity_per_acre, price_per_kg, phone_no,
                            location,
                            org_name, vendor_crop_counter, category, region, material_status
                        ))
            mysql.connection.commit()
            cur.close()
            flash('Product submitted successfully', 'success')
            return redirect(url_for('vendor_product_verification'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            flash('Product already exists', 'danger')
            return redirect(url_for('vendor_product_verification'))
    return render_template('vendor_product_verification.html', categories=categories)


# VENDOR LIST
@app.route('/client-list/', methods=['POST', 'GET'])
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
        # dob = request.form['dob']
        phone_no = request.form['phone_no']
        id_no = request.form['id_no']
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
            cur.execute("INSERT INTO habahaba_trial.users (f_name, l_name, gender, phone_no, id_no, email,"
                        " password, date_registered, size_of_land, location_of_land, land_scale) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (f_name, l_name, gender, phone_no, id_no, email, passwords, date_registered, size_of_land,
                         land_location, scale))
            mysql.connection.commit()
            cur.close()

            vendor_text_msg(phone_no, password)
            flash(f'User will receive their password on {phone_no} ', 'success')
            return redirect(url_for('vendor_user_onboarding'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            flash('This email already exists, please try another one', 'danger')
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
        f"SELECT sender_name, sender_email, sender_phone, amount_sent, saving_target, date_sent FROM"
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
        vendor_email = request.form['vendor_email']
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

        cur = mysql.connection.cursor()
        cur.execute(
            "INSERT INTO habahaba_trial.offers (vendor_name, vendor_id, vendor_email, org_name, offer_name, percentage_off"
            ", valid_until, region_available, active_from, offer_status, campaign_name, material_ids) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                vendor_name, vendor_id, vendor_email, org_name, offer_name, percentage_off, valid_until, region, today,
                offer_status, campaign_name, material_id
            ))
        mysql.connection.commit()
        cur.close()
        flash('Offer submitted successfully', 'success')
        return redirect(url_for('vendors_offer_list'))
    return render_template('vendors-offers.html', products=products, offers=offers, counties=counties)


@app.route('/float-summary/', methods=['GET'])
@is_vendor_logged_in
def v_float_summary():
    return render_template('a_float_summary.html')


@app.route('/float-summary-json/', methods=['GET'])
@is_vendor_logged_in
def v_float_summary_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT sum(quantity_redeemed), sum(amount_sent), sum(amount_redeemed), sum(amount_sent - payments_table.amount_redeemed) "
        f"FROM habahaba_trial.payments_table WHERE vendor_id = '{session['vendor_id']}' ")
    summary = cur.fetchall()
    cur.close()
    return datatable(summary)


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
    cur.execute(f"SELECT client_name,client_name, client_email, client_phone, vendor_crop"
                f" FROM habahaba_trial.partnership WHERE vendor_id = '{session['vendor_id']}' ")
    users = cur.fetchall()
    cur.close()
    return datatable(users)


@app.route('/vendor-partners-json/', methods=['GET'])
@is_vendor_logged_in
def vendor_partners_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT  max(client_name), max(client_phone), max(vendor_crop) FROM habahaba_trial.partnership"
        f" WHERE vendor_id = '{session['vendor_id']}' GROUP BY client_name")
    partners = cur.fetchall()
    cur.close()
    return datatable(partners)


@app.route('/vendor-user-transactions-json/', methods=['GET'])
@is_vendor_logged_in
def vendor_user_transactions_json():
    # sender_name, sender_email, sender_phone, amount_sent, saving_target, date_sent
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT sender_name, sender_email, sender_phone, amount_sent, saving_target, date_sent FROM"
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
    cur.execute(f"SELECT sender_name, sender_email, sender_phone, amount_sent, saving_target, date_sent"
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
            # return jsonify({'message': 'Failed to login: Username -Password pair do not match'})
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
        # l_name = session['l_name']
        x = '0'
        cur.execute("UPDATE habahaba_trial.users SET online=%s WHERE user_id=%s ", (x, uid))

        session.clear()
        flash(f'You are now logged out {f_name}', 'red lighten-2')
        return redirect(url_for('user_login'))
    return redirect(url_for('user_login'))


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[service worker registration]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
@app.route('/sw.js', methods=['GET'])
def sw():
    return current_app.send_static_file('sw.js')


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
    cur.execute(f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}' ")
    user_items = cur.fetchall()
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

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.payments_table "
                "CROSS JOIN habahaba_trial.partnership p on payments_table.vendor_email = p.vendor_email")
    joint_values = cur.fetchall()
    cur.close()

    members_json = json.dumps(all_members)

    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}' ORDER BY payment_id DESC ")
    partners = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.partnership WHERE client_id = '{session['user_id']}'")
    partnership_id = cur.fetchall()
    cur.close()

    this_month = datetime.now().month
    this_year = datetime.now().year

    if request.method == 'POST':
        # vendor details
        vendor_id = request.form['vendor_id']
        vendor_name = request.form['vendor_name']
        vendor_email = request.form['vendor_email']
        vendor_phone = request.form['vendor_phone']
        crop_name = request.form['crop_name']
        location = request.form['location']
        payment_method = request.form['payment_method']
        acc_number = request.form['acc_number']
        vendor_org = request.form['vendor_org']
        # client details
        client_id = request.form['client_id']
        client_name = request.form['client_name']
        client_phone = request.form['client_phone']
        client_email = request.form['client_email']
        counter_column = f"{vendor_id} {client_id} {crop_name} {this_month} {this_year}"

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.partnership(vendor_id, vendor_name, vendor_email, vendor_phone,"
                        "vendor_org, vendor_crop, vendor_location, payment_method, acc_number, client_id,"
                        "client_name, client_email, client_phone, counter_column) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            vendor_id, vendor_name, vendor_email, vendor_phone, vendor_org, crop_name,
                            location, payment_method, acc_number, client_id, client_name, client_email,
                            client_phone, counter_column
                        ))
            mysql.connection.commit()
            cur.close()
            flash(f'{crop_name} Partner selected', 'green lighten-2')
            return redirect(url_for('targets'))
        except:
            flash(f'{vendor_name} is already your partner for {crop_name}', 'yellow darken-3')
            return redirect(url_for('targets'))
    return render_template('ukulima_targets.html', vendors=vendors, all_members=all_members, partners=partners,
                           members_json=members_json, joint_values=joint_values)


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
    cur.execute(f"SELECT offer_id FROM habahaba_trial.redirecting_table WHERE client_id = '{session['user_id']}'")
    offer_id = cur.fetchone()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(
        f"""SELECT * FROM habahaba_trial.offers INNER JOIN habahaba_trial.materials ON habahaba_trial.offers.vendor_id = habahaba_trial.materials.vendor_id
        WHERE habahaba_trial.offers.vendor_id = '{session['vendor_id']}' AND habahaba_trial.offers.offer_status = 'Accepted'
        AND habahaba_trial.offers.offer_id = '{offer_id['offer_id']}' """)
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
        f"SELECT * FROM habahaba_trial.partnership WHERE client_id = '{session['user_id']}' ORDER BY partnership_id DESC ")
    partnered_vendors = cur.fetchall()
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

    # cur = mysql.connection.cursor()
    # cur.execute(f"SELECT * FROM habahaba_trial.materials WHERE material_id = '{client['material_id']}' ")
    # vendor_details = cur.fetchone()
    # cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.materials "
                f"INNER JOIN habahaba_trial.vendors ON materials.vendor_id = vendors.vendor_id "
                f"WHERE material_id = '{client['material_id']}'")
    vendor_details = cur.fetchone()
    cur.close()

    this_month = datetime.now().month
    this_year = datetime.now().year

    if request.method == 'POST':
        # vendor details
        vendor_id = request.form['vendor_id']
        vendor_name = request.form['vendor_name']
        vendor_email = request.form['vendor_email']
        vendor_phone = request.form['vendor_phone']
        crop_name = request.form['crop_name']
        location = request.form['location']
        payment_method = request.form['payment_method']
        acc_number = request.form['acc_number']
        vendor_org = request.form['vendor_org']
        save_until = request.form['save_until']
        category = request.form['category']

        price_per_kg = request.form['price_per_kg']
        quantity_per_acre = request.form['quantity_per_acre']

        # client details
        client_id = request.form['client_id']
        client_name = request.form['client_name']
        client_phone = request.form['client_phone']
        client_email = request.form['client_email']
        saving_target = request.form['payment_required']
        amount = 0

        counter_column = f"{vendor_id} {client_id} {crop_name} {this_month} {this_year}"
        client_vendor_crop = f"{vendor_id} {client_id} {crop_name}"

        # time the user sends the money
        today = date.today()
        right_now = datetime.now()
        now = right_now.strftime("%H:%M:%S")
        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.partnership(vendor_id, vendor_name, vendor_email, vendor_phone,"
                        "vendor_org, vendor_crop, vendor_location, payment_method, acc_number, client_id,"
                        "client_name, client_email, client_phone, counter_column, saving_target, save_until, category) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s, %s, %s)",
                        (
                            vendor_id, vendor_name, vendor_email, vendor_phone, vendor_org, crop_name,
                            location, payment_method, acc_number, client_id, client_name, client_email,
                            client_phone, counter_column, saving_target, save_until, category
                        ))
            mysql.connection.commit()
            cur.close()

            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.payments_table (vendor_id, vendor_name, vendor_email,"
                        "vendor_phone, org_name, sender_id, sender_name, sender_email, "
                        "sender_phone, amount_sent, date_sent, time_sent, date_and_time, saving_target,"
                        " payment_for, client_vendor_crop, quantity_per_acre, price_per_kg, redeemable_amount, category) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ", (
                            vendor_id, vendor_name, vendor_email, vendor_phone, vendor_org,
                            client_id, client_name, client_email, client_phone, amount, today, now, right_now,
                            saving_target, crop_name, client_vendor_crop, quantity_per_acre, price_per_kg, amount,
                            category
                        ))
            mysql.connection.commit()
            cur.close()
            flash(f'{crop_name} Partner selected', 'green lighten-2')
            return redirect(url_for('ukulima_partners'))
        except:
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
        f"SELECT org_name, amount_sent, date(date_and_time) as date_sent, payment_for, (category) as cat, amount_saved_daily,"
        f" vendor_payment FROM habahaba_trial.payment_transactions WHERE sender_id = '{session['user_id']}' ")
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
    cur.execute(f"SELECT payment_id, sender_name, amount_sent, saving_target, amount_redeemed, redemption_date "
                f"FROM habahaba_trial.payments_table WHERE vendor_id = '{session['vendor_id']}'")
    redemptionSummary = cur.fetchall()
    cur.close()
    return datatable(redemptionSummary)


@app.route('/redemption-summary/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_redemption_summary():
    return render_template('v_redemption_summary.html')


@app.route('/savings-achievement-summary-json/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_savings_vs_achievement_summary_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""SELECT max(category), max(category) as category,count(*), sum(amount_sent), 
    format(sum(amount_sent)/ sum(saving_target) * 100, 2) as achievment_rate
     FROM habahaba_trial.payments_table WHERE vendor_id = {session['vendor_id']} GROUP BY category""")
    savings_vs_achievement = cur.fetchall()
    cur.close()
    return datatable(savings_vs_achievement)


@app.route('/savings-achievement-summary/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_savings_vs_achievement_summary():
    return render_template('v_savings_vs_achievment.html')


@app.route('/saving-insight-json/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_saving_insight_json():
    cur = mysql.connection.cursor()
    cur.execute(f"""
    SELECT max(category), max(category), sum(amount_sent), 
    format(avg(saving_target / (price_per_kg * payments_table.quantity_per_acre)), 2) 
    FROM habahaba_trial.payments_table WHERE vendor_id = '{session['vendor_id']}' GROUP BY category
    """)
    vendor_savings_insight = cur.fetchall()
    cur.close()
    return datatable(vendor_savings_insight)


@app.route('/savings-insight/', methods=['POST', 'GET'])
@is_vendor_logged_in
def v_savings_insight():
    return render_template('v_saving_insight.html')


@app.route('/saving-report-json/', methods=['GET'])
@is_vendor_logged_in
def saving_report_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT transaction_id, sender_name, amount_saved_daily, amount_sent, category , payment_for  "
        f"FROM habahaba_trial.payment_transactions ")
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
    cur.execute(
        "SELECT  max(vendor_name), max(sender_name), max(saving_target), max(amount_sent), max(amount_sent) FROM habahaba_trial.payments_table GROUP BY sender_phone")
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
    cur.execute(
        f"SELECT payment_id, org_name, payment_for, redeemable_amount, saving_target, quantity_redeemed, amount_redeemed,"
        f"sender_id, sender_name, sender_phone, vendor_id, vendor_name, vendor_phone, redeemable_amount, quantity_per_acre,"
        f"price_per_kg, amount_redeemed, quantity_redeemed, redeemable_amount "
        f" FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}' "
        f"ORDER BY payment_id DESC")
    redeemable_items = cur.fetchall()
    cur.close()
    return json.dumps(redeemable_items)


@app.route('/redemption/', methods=['POST', 'GET'])
@is_user_logged_in
def redemption():
    # time the user sends the money
    today = date.today()
    right_now = datetime.now()
    current_time = right_now.strftime("%H:%M:%S")

    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}'"
        f"AND amount_sent != saving_target AND amount_sent > 1 ORDER BY payment_id DESC ")
    redeemable_items = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT payment_for FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}' ORDER BY payment_id DESC ")
    items = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        # redeemable_amount = request.form['redeemable_amount']
        # payment_id = request.form['payment_id']
        # quantity_redeemed = request.form['redeem']
        # price_per_kg = request.form['price_per_kg']

        # new_values
        payment_id = request.form['payment_id']
        client_id = request.form['client_id']
        client_name = request.form['client_name']
        client_phone = request.form['client_phone']
        vendor_id = request.form['vendor_id']
        vendor_org = request.form['vendor_org']
        item_redeemed = request.form['item_redeemed']
        amount_to_redeem = request.form['amount_to_redeem']
        redeemable_amount = request.form['redeemable_amount']
        amountRedeemed = request.form['amount_redeemed']
        quantity_redeemed = request.form['quantity_redeemed']
        quantity_per_acre = request.form['quantity_per_acre']

        client_vendor_crop = f"{client_id} {vendor_id} {item_redeemed}"

        cur = mysql.connection.cursor()
        cur.execute(f"SELECT * FROM habahaba_trial.payments_table WHERE client_vendor_crop = '{client_vendor_crop}'")
        redemption_details = cur.fetchone()
        cur.close()

        cur = mysql.connection.cursor()
        cur.execute(f"SELECT category FROM habahaba_trial.payments_table WHERE payment_id = '{payment_id}'")
        payment_category = cur.fetchone()
        cur.close()
        my_category = payment_category['category']

        if amount_to_redeem < redeemable_amount:
            # amount_redeemed = redemption_details['amount_redeemed'] + int(amount_to_redeem)
            # quantity_to_redeem = int(amount_to_redeem) / int(redemption_details['quantity_per_acre'])
            # quantity_redeemed = (int(amount_to_redeem) / int(redemption_details['quantity_per_acre'])
            #                      + redemption_details['quantity_redeemed'])
            # redeemable = int(redemption_details['redeemable_amount']) - int(amount_to_redeem)

            amount_redeemed = int(amountRedeemed) + int(amount_to_redeem)
            quantity_to_redeem = round(float(int(amount_to_redeem) / int(quantity_per_acre)), 2)
            quantity_redeemed = round(float((int(amount_to_redeem) / int(quantity_per_acre)) + int(quantity_redeemed)),
                                      2)
            redeemable = int(redeemable_amount) - int(amount_to_redeem)
            # inserting into redemption table
            cur = mysql.connection.cursor()
            cur.execute(
                "INSERT INTO habahaba_trial.redemption (vendor_id, vendor_org, client_id, client_name, client_phone,"
                " payment_for, amount_redeemed, date_redeemed, time_redeemed, quantity_redeemed, category)"
                " VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                    vendor_id, vendor_org, client_id, client_name, client_phone, item_redeemed, amount_to_redeem, today,
                    current_time, quantity_redeemed, my_category
                ))
            mysql.connection.commit()
            cur.close()

            # update payments table
            cur = mysql.connection.cursor()
            cur.execute("""UPDATE habahaba_trial.payments_table
            SET amount_redeemed=%s, quantity_redeemed=%s, redeemable_amount=%s, redemption_date=%s
            WHERE payment_id=%s
            """, (
                amount_redeemed, quantity_redeemed, redeemable, today, payment_id
            ))
            mysql.connection.commit()
            cur.close()
            flash(f'Redeemed {quantity_to_redeem}Kgs of {item_redeemed} Successfully', 'green lighten-2')
            return redirect(url_for('redemption'))
        else:
            flash(f'You can redeem a maximum of {redemption_details["redeemable_amount"]} KGs of {item_redeemed}')
            return redirect(url_for('redemption'))
    return render_template('ukulima_redemption.html', redeemable_items=redeemable_items, items=items)


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
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id= '{session['user_id']}' ORDER BY payment_id DESC ")
    partners = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT amount_sent FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}' "
        f"ORDER BY payment_id DESC ")
    previous_value = cur.fetchone()
    cur.close()

    # list of crops that a client is subscribed to
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT distinct payment_for FROM habahaba_trial.payments_table"
                f" WHERE amount_sent < saving_target AND sender_id = '{session['user_id']}' ")
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
        vendor_id = request.form['vendor_id']
        vendor_name = request.form['vendor_name']
        # vendor_email = request.form['vendor_email']
        vendor_phone = request.form['vendor_phone']
        vendor_org = request.form['vendor_org']
        vendor_crop = request.form['vendor_crop']
        vendor_commission = request.form['commission']
        category = request.form['category']
        selected_crop = request.form['selected_crop']

        # crop_name = request.form['payment_for']

        saving_target = request.form['saving_target']
        amount_sent = request.form['amount_sent']

        # client details
        payment_id = request.form['payment_id']
        client_id = request.form['client_id']
        client_name = request.form['client_name']
        # client_email = request.form['client_email']
        client_phone = request.form['client_phone']
        value_entered = request.form['payment']
        former_value = request.form['amount_sent']
        # amount = int(value_entered) + int(previous_value['amount_sent'])
        amount = int(value_entered) + int(former_value)

        commission = int(value_entered) * (int(vendor_commission) / 100)
        payment = int(value_entered) - commission

        client_vendor_crop = f"{vendor_id} {client_id} {vendor_crop}"
        date_counter = f"{this_month} {this_year}"

        # if float(amount) > (float(saving_target) - float(amount_sent)):
        if float(amount) > float(saving_target):
            flash('Amount entered surpasses the target', 'orange lighten-2 white-text')
            return redirect(url_for('ukulima_funds'))
        else:
            # fetching the redeemable amount
            cur = mysql.connection.cursor()
            cur.execute(
                f"SELECT * FROM habahaba_trial.payments_table WHERE payment_id = '{payment_id}' ")
            redeemable = cur.fetchone()
            cur.close()

            redeemable_amount = int(value_entered) + int(redeemable['redeemable_amount'])

            payment_amount = float(redeemable['amount_sent']) + float(value_entered)

            cur = mysql.connection.cursor()
            cur.execute("""UPDATE habahaba_trial.payments_table 
            SET amount_sent=%s, date_sent=%s, time_sent=%s, date_and_time=%s, redeemable_amount=%s
            WHERE payment_id=%s""", (
                payment_amount, today, now, right_now, redeemable_amount, payment_id
            ))
            mysql.connection.commit()
            cur.close()

            # add payment to transaction table
            # try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.payment_transactions (vendor_id, vendor_name,"
                        "vendor_phone, org_name, sender_id, sender_name, "
                        "sender_phone, amount_sent, date_sent, time_sent, date_and_time, saving_target, payment_for,"
                        " date_counter, amount_saved_daily, category ) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ", (
                            vendor_id, vendor_name, vendor_phone, vendor_org, client_id, client_name,
                            client_phone, amount, today, now, right_now, saving_target, selected_crop,
                            date_counter, value_entered, category
                        ))
            mysql.connection.commit()
            cur.close()

            # except (MySQLdb.Error, MySQLdb.Warning) as e:
            #     flash("Payment failed, please reload the page and try again.", "red lighten-2")
            #     return redirect(url_for('ukulima_funds'))

            # try:
            # inserting into commissions table
            cur = mysql.connection.cursor()
            cur.execute(f"""
            INSERT INTO habahaba_trial.commission (vendor_id, client_id, vendor_name, sender_name, 
            item_name, amount_sent, commission_percentage, vendor_amount, commission, category, date_paid)
             VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                vendor_id, client_id, redeemable['org_name'], client_name, selected_crop, value_entered,
                vendor_commission, payment, commission, category, today
            ))
            mysql.connection.commit()
            cur.close()
            flash(f'Amount sent successfully {vendor_crop}', 'green lighten-2 white-text')
            return redirect(url_for('ukulima_funds'))
    return render_template('ukulima_funds.html', partners=partners, client_crops=client_crops)


@app.route('/ukulima-funds-json/', methods=['POST', 'GET'])
@is_user_logged_in
def ukulima_funds_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT payment_id, payments_table.vendor_id, vendor_name, vendor_phone, payments_table.org_name, sender_id, sender_name, sender_phone,"
        f" amount_sent, saving_target, payment_for, quantity_per_acre, price_per_kg, category, vendors.commission, format(amount_sent / price_per_kg, 2) as current_quantity,"
        f" format(saving_target/payments_table.price_per_kg, 2) as target_quantity "
        f"FROM habahaba_trial.payments_table INNER JOIN habahaba_trial.vendors ON "
        f"payments_table.vendor_id = vendors.vendor_id WHERE sender_id= '{session['user_id']}' ")
    partners = cur.fetchall()
    cur.close()
    return json.dumps(partners)


@app.route('/funds-testing/', methods=['POST', 'GET'])
@is_user_logged_in
def funds_testing():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id= '{session['user_id']}' ORDER BY payment_id DESC ")
    partners = cur.fetchall()
    cur.close()
    return json.dumps(partners)


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
consumer_key = 'AJhUyehvuTGoiANeIo8qW1hNPKdA10kS'
consumer_secret = 'BzMPjAd4yKr97xhv'
base_url = 'http://197.232.79.73:801'


def ac_token():
    mpesa_auth_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    data = (requests.get(mpesa_auth_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))).json()
    return data


@app.route('/token/', methods=['POST', 'GET'])
def tokens():
    data = ac_token()
    print(data)
    return data


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


timestamp = datetime.now()
times = timestamp.strftime("%Y%m%d%H%M%S")


@app.route('/pay/', methods=['POST', 'GET'])
def mpesa_express():
    if request.method == 'POST':
        # headers = {
        #     'Content-Type': 'application/json',
        #     'Authorization': f'Bearer {ac_token()}'
        # }
        my_endpoint = "https://5533-197-232-79-73.in.ngrok.io"

        amount = request.form['amount']
        phone = request.form['phone']

        endpoint = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        access_token = ac_token()
        headers = {
            "Content-Type": "application/json",
            # "Authentication": f"Bearer {ac_token()}"
            "Authorization": f"Bearer {ac_token()}"
        }

        password = "MTc0Mzc5YmZiMjc5ZjlhYTliZGJjZjE1OGU5N2RkNzFhNDY3Y2QyZTBjODkzMDU5YjEwZjc4ZTZiNzJhZGExZWQyYzkxOTIwMjIxMTI0MDk0NDE5"
        password = base64.b64encode(password.encode('utf-8'))

        # data = {
        #     "BusinessShortCode": 174379,
        #     "Password": "MTc0Mzc5YmZiMjc5ZjlhYTliZGJjZjE1OGU5N2RkNzFhNDY3Y2QyZTBjODkzMDU5YjEwZjc4ZTZiNzJhZGExZWQyYzkxOTIwMjIxMTI4MTE0MzE5",
        #     "Timestamp": "20221128114319",
        #     "TransactionType": "CustomerPayBillOnline",
        #     "Amount": amount,
        #     "PartyA": phone,
        #     "PartyB": 174379,
        #     "PhoneNumber": phone,
        #     "CallBackURL": my_endpoint + "/callback/",
        #     "AccountReference": "CompanyXLTD",
        #     "TransactionDesc": "Payment of X"
        # }

        data = {
            "BusinessShortCode": 174379,
            "Password": "MTc0Mzc5YmZiMjc5ZjlhYTliZGJjZjE1OGU5N2RkNzFhNDY3Y2QyZTBjODkzMDU5YjEwZjc4ZTZiNzJhZGExZWQyYzkxOTIwMjIxMTI4MTE0MzE5",
            "Timestamp": "20221128114319",
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
        flash('Success')
        print(times)
        # return res.json()
        return my_res.json()


# consume M-PESA Express Callback
@app.route('/callback/', methods=['POST', 'GET'])
def incoming():
    data = request.get_json()
    print(data)
    return "ok"


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
