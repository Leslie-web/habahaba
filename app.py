# for daraja api
import base64
import random

import MySQLdb
import requests
import json
import bcrypt
# import csv
from requests.auth import HTTPBasicAuth

from flask import *
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from functools import wraps
from datetime import date, datetime

# ngrok
from flask_ngrok import run_with_ngrok

app = Flask(__name__)
run_with_ngrok(app)

mysql = MySQL()
app.secret_key = 'erxycutvhkbjlnk'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'habahaba_trial'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql.init_app(app)


# BLOCK ADMIN ROUTES
def is_admin_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('admin_login'))

    return wrap


def not_admin_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'admin_logged_in' in session:
            return redirect(url_for('admin_login'))
        else:
            return f(*args, **kwargs)

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
            return redirect(url_for('user_login'))
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
            return redirect(url_for('index'))
        else:
            return f(*args, **kwargs)

    return wrap


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
    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        email = request.form['email']
        residence = request.form['residence']
        dob = request.form['dob']
        phone_no = request.form['phone_no']
        password = sha256_crypt.encrypt(str(request.form['password']))

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.admin (f_name, l_name, email, residence, dob, phone_no,"
                        " password) VALUES (%s, %s, %s, %s, %s, %s, %s)", (
                            f_name, l_name, email, residence, dob, phone_no, password
                        ))
            mysql.connection.commit()
            cur.close()
            return redirect(url_for('admin_login'))
        except:
            flash('This email already exists, Please enter another one', 'red lighten-2')
            return redirect(url_for('admin_registration'))
    return render_template('admin_registration.html')


# admin login
@app.route('/admin-login/', methods=['POST', 'GET'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM habahaba_trial.admin WHERE email=%s", [email])

        if result > 0:
            data = cur.fetchone()
            password = data['password']
            email = data['email']
            uid = data['admin_id']
            f_name = data['f_name']
            l_name = data['l_name']
            phone_no = data['phone_no']

            if sha256_crypt.verify(password_candidate, password):
                session['admin_logged_in'] = True
                session['admin_id'] = uid
                session['email'] = email
                session['f_name'] = f_name
                session['l_name'] = l_name
                session['phone_no'] = phone_no
                x = '1'

                cur.execute("UPDATE habahaba_trial.admin SET online=%s WHERE admin_id=%s", (x, uid))
                return redirect(url_for('alan_code'))
            else:
                flash('Incorrect Password, please try again', 'danger')
                return redirect(url_for('admin_login'))
        else:
            flash('This email is not registered, please try again', 'danger')
            cur.close()
            return redirect(url_for('admin_login'))
    return render_template('admin_login.html')


# admin logout
@app.route('/admin-logout/', methods=['POST', 'GET'])
def admin_logout():
    if 'admin_id' in session:
        cur = mysql.connection.cursor()
        uid = session['admin_id']
        f_name = session['f_name']
        x = '0'
        cur.execute("UPDATE habahaba_trial.admin SET online=%s WHERE admin_id=%s ", (x, uid))
        flash(f'You are now logged out {f_name}', 'danger')
        return redirect(url_for('admin_login'))
    return redirect(url_for('admin_login'))


# admin home page
@app.route('/template/', methods=['POST', 'GET'])
def alan_code():
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
                           offers=offers, payments=payments, transactions=transactions
                           )


# VENDOR SETUP
@app.route('/vendor-setup/', methods=['POST', 'GET'])
def admin_vendor_setup():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.vendors WHERE acc_status = 'pending'")
    org_name = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        id_no = request.form['id_no']
        phone_no = request.form['phone_no']
        gender = request.form.get('gender')
        payment_method = request.form.get('payment_method')
        acc_number = request.form['acc_number']
        org_location = request.form['org_location']
        commission = request.form['commission']
        organization_name = request.form['org_name']

        vendor_status = 'set_up'

        # try:
        cur = mysql.connection.cursor()
        cur.execute(f"""
        UPDATE habahaba_trial.vendors
        SET f_name=%s, l_name=%s, id_no=%s, gender=%s, phone_no=%s, payment_method=%s, acc_number=%s, location=%s,
         commission=%s, acc_status=%s
         WHERE org_name='{organization_name}' AND acc_status = 'pending'
        """, (
            f_name, l_name, id_no, gender, phone_no, payment_method, acc_number, org_location, commission,
            vendor_status
        ))
        mysql.connection.commit()
        cur.close()

        flash("Vendor has been set up successfully", "success")
        return redirect(url_for('admin_vendor_setup'))
        # except (MySQLdb.Error, MySQLdb.Warning) as e:
        #     print(e)
        #     flash('Duplicate entry entered, please try again', 'warning')
        #     return redirect(url_for('admin_vendor_setup'))
    return render_template('admin_vendor_setup.html', org_name=org_name)


@app.route('/create-user/', methods=['POST'])
def admin_create_user():
    return render_template('admin-create-users.html')


# ADMIN TRANSACTIONS
@app.route('/transactions/', methods=['POST', 'GET'])
def admin_transactions():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.payment_transactions")
    transactions = cur.fetchall()
    cur.close()
    return render_template('admin_transactions.html', transactions=transactions)


# ADMIN HOMEPAGE
@app.route('/admin-homepage/', methods=['POST', 'GET'])
def admin_homepage():
    return render_template('admin_homepage.html')


# ADMIN PRODUCT VERIFICATION
@app.route('/product-verification/', methods=['POST', 'GET'])
def admin_product_verification():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials ORDER BY material_id DESC ")
    vendor_products = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        ids = request.form['ids']
        action_selected = request.form.get('action_selected')

        cur = mysql.connection.cursor()
        cur.execute("UPDATE habahaba_trial.materials SET material_status=%s WHERE material_id=%s",
                    (action_selected, ids))
        mysql.connection.commit()
        cur.close()
        flash('Action completed successfully', 'green lighten-2')
        return redirect(url_for('admin_product_verification'))
    return render_template('admin_product_verification.html', vendor_products=vendor_products)


# ADMIN VIEW USERS
@app.route('/admin-view-users/', methods=['POST', 'GET'])
def admin_view_users():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.users")
    users = cur.fetchall()
    cur.close()
    return render_template('adimn_view_users.html', users=users)


# ADMIN VENDOR REPORTS
@app.route('/vendor-reports/', methods=['POST', 'GET'])
def admin_vendor_reports():
    return render_template('admin_vendor_report.html')


# ADMIN PRODUCT VALIDATION
@app.route('/admin-product-validation/', methods=['POST', 'GET'])
def product_validation():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials ORDER BY material_id DESC ")
    vendor_products = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        material_id = request.form['material_id']
        action_selected = request.form.get('action_selected')

        cur = mysql.connection.cursor()
        cur.execute("UPDATE habahaba_trial.materials SET material_status=%s WHERE material_id=%s",
                    (action_selected, material_id))
        mysql.connection.commit()
        cur.close()

        flash('Action completed successfully', 'success')
        return redirect(url_for('product_validation'))
    return render_template('admin_product_validation.html', vendor_products=vendor_products)


# ADMIN VIEW VENDORS
@app.route('/admin-view-vendors/', methods=['POST', 'GET'])
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


# ADMIN VIEW PRODUCTS
@app.route('/admin-view-products/', methods=['POST', 'GET'])
def admin_view_products():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials WHERE material_status = 'accepted'")
    products = cur.fetchall()
    cur.close()
    return render_template('admin_view_products.html', products=products)


# ADMIN VIEW OFFERS
@app.route('/admin-view-offers/', methods=['POST', 'GET'])
def admin_view_offers():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.offers WHERE offer_status = 'accepted'")
    offers = cur.fetchall()
    cur.close()
    return render_template('admin_view_offers.html', offers=offers)


# ADMIN SET REGIONS
@app.route('/set-regions/', methods=['POST', 'GET'])
def admin_set_regions():
    return render_template('admin_set_regions.html')


# ADMIN PRODUCT CATEGORIES
@app.route('/product-categories/', methods=['POST', 'GET'])
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
def delete_category():
    if request.method == 'POST':
        category_id = request.form['category_id']

        cur = mysql.connection.cursor()
        cur.execute(f"DELETE FROM habahaba_trial.category WHERE category_id ='{category_id}' ")
        mysql.connection.commit()
        cur.close()
        flash("Category Deleted successfully", "success")
        return redirect(url_for('admin_product_categories'))


# admin delete product
# @app.route('/delete-product/<string:id_data>', methods=['POST', 'GET'])
# def delete_category(id_data):
#     cur = mysql.connection.cursor()
#     cur.execute("DELETE FROM habahaba_trial.materials WHERE material_id=%s" % id_data)
#     mysql.connection.commit()
#     return redirect(url_for('category'))


@app.route('/vendor-reports-json/', methods=['POST', 'GET'])
def admin_vendor_reports_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT vendor_id, vendor_name, org_name, sender_id, sender_name, amount_sent, saving_target,"
        " payment_for FROM habahaba_trial.payment_transactions")
    transactions = cur.fetchall()
    cur.close()
    return json.dumps(transactions)


@app.route('/admin-transactions-json/', methods=['GET'])
def admin_transactions_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT max(sender_name), sender_phone, max(org_name), sum(amount_sent), max(sender_id),"
        " max(payment_for) FROM habahaba_trial.payment_transactions group by sender_phone")
    transactions = cur.fetchall()
    cur.close()
    return datatable(transactions)


@app.route('/admin-view-categories/', methods=['GET'])
def view_categories():
    cur = mysql.connection.cursor()
    cur.execute("SELECT category_id, category_name, sub_category FROM habahaba_trial.category")
    categories = cur.fetchall()
    cur.close()
    return datatable(categories)


counties = [{
    "name": "Mombasa",
    "code": 1,
    "capital": "Mombasa City"
}, {
    "name": "Kwale",
    "code": 2,
    "capital": "Kwale"
}, {
    "name": "Kilifi",
    "code": 3,
    "capital": "Kilifi"
}, {
    "name": "Tana River",
    "code": 4,
    "capital": "Hola"

}, {
    "name": "Lamu",
    "code": 5,
    "capital": "Lamu"
}, {
    "name": "Taita-Taveta",
    "code": 6,
    "capital": "Voi"
}, {
    "name": "Garissa",
    "code": 7,
    "capital": "Garissa"
}, {
    "name": "Wajir",
    "code": 8,
    "capital": "Wajir"
}, {
    "name": "Mandera",
    "code": 9,
    "capital": "Mandera"
}, {
    "name": "Marsabit",
    "code": 10,
    "capital": "Marsabit"
}, {
    "name": "Isiolo",
    "code": 11,
    "capital": "Isiolo"
}, {
    "name": "Meru",
    "code": 12,
    "capital": "Meru"
}, {
    "name": "Tharaka-Nithi",
    "code": 13,
    "capital": "Chuka"
}, {
    "name": "Embu",
    "code": 14,
    "capital": "Embu"
}, {
    "name": "Kitui",
    "code": 15,
    "capital": "Kitui"
}, {
    "name": "Machakos",
    "code": 16,
    "capital": "Machakos"
}, {
    "name": "Makueni",
    "code": 17,
    "capital": "Wote"
}, {
    "name": "Nyandarua",
    "code": 18,
    "capital": "Ol Kalou"
}, {
    "name": "Nyeri",
    "code": 19,
    "capital": "Nyeri"
}, {
    "name": "Kirinyaga",
    "code": 20,
    "capital": "Kerugoya/Kutus"
}, {
    "name": "Murang'a",
    "code": 21,
    "capital": "Murang'a"
}, {
    "name": "Kiambu",
    "code": 22,
    "capital": "Kiambu"
}, {
    "name": "Turkana",
    "code": 23,
    "capital": "Lodwar"
}, {
    "name": "West Pokot",
    "code": 24,
    "capital": "Kapenguria"
}, {
    "name": "Samburu",
    "code": 25,
    "capital": "Maralal"
}, {
    "name": "Trans-Nzoia",
    "code": 26,
    "capital": "Kitale"
}, {
    "name": "Uasin Gishu",
    "code": 27,
    "capital": "Eldoret"
}, {
    "name": "Elgeyo-Marakwet",
    "code": 28,
    "capital": "Iten"
}, {
    "name": "Nandi",
    "code": 29,
    "capital": "Kapsabet"
}, {
    "name": "Baringo",
    "code": 30,
    "capital": "Kabarnet"
}, {
    "name": "Laikipia",
    "code": 31,
    "capital": "Rumuruti"
}, {
    "name": "Nakuru",
    "code": 32,
    "capital": "Nakuru"
}, {
    "name": "Narok",
    "code": 33,
    "capital": "Narok"
}, {
    "name": "Kajiado",
    "code": 34
}, {
    "name": "Kericho",
    "code": 35,
    "capital": "Kericho"
}, {
    "name": "Bomet",
    "code": 36,
    "capital": "Bomet"
}, {
    "name": "Kakamega",
    "code": 37,
    "capital": "Kakamega"
}, {
    "name": "Vihiga",
    "code": 38,
    "capital": "Vihiga"
}, {
    "name": "Bungoma",
    "code": 39,
    "capital": "Bungoma"
}, {
    "name": "Busia",
    "code": 40,
    "capital": "Busia"
}, {
    "name": "Siaya",
    "code": 41,
    "capital": "Siaya"
}, {
    "name": "Kisumu",
    "code": 42,
    "capital": "Kisumu"
}, {
    "name": "Homa Bay",
    "code": 43,
    "capital": "Homa Bay"
}, {
    "name": "Migori",
    "code": 44,
    "capital": "Migori"
}, {
    "name": "Kisii",
    "code": 45,
    "capital": "Kisii"
}, {
    "name": "Nyamira",
    "code": 46,
    "capital": "Nyamira"
}, {
    "name": "Nairobi",
    "code": 47,
    "capital": "Nairobi City"
}]


@app.route('/regions-json/', methods=['POST', 'GET'])
def regions_json():
    return counties


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[VENDOR DETAILS]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
# VENDOR LOGIN
@app.route('/vendor-login/', methods=['POST', 'GET'])
def vendor_login():
    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM habahaba_trial.vendors WHERE email=%s", [email])

        if result > 0:
            data = cur.fetchone()
            password = data['passwords']
            email = data['email']
            phone_no = data['phone_no']
            uid = data['vendor_id']
            f_name = data['f_name']
            l_name = data['l_name']
            payment_method = data['payment_method']
            acc_number = data['acc_number']
            org_name = data['org_name']
            location = data['location']
            id_no = data['id_no']
            general_industry = data['general_industry']

            if sha256_crypt.verify(password_candidate, password):
                session['vendor_logged_in'] = True
                session['vendor_id'] = uid
                session['email'] = email
                session['f_name'] = f_name
                session['l_name'] = l_name
                session['payment_method'] = payment_method
                session['acc_number'] = acc_number
                session['org_name'] = org_name
                session['phone_no'] = phone_no
                session['location'] = location
                session['id_no'] = id_no
                session['general_industry'] = general_industry
                x = '1'

                cur.execute("UPDATE habahaba_trial.vendors SET online=%s WHERE vendor_id=%s", (x, uid))
                return redirect(url_for('vendor_home'))
            else:
                flash('Incorrect password, please try again', 'yellow lighten-3')
                return render_template('vendor_login.html')
        else:
            flash('This email is not registered, please register first', 'red lighten-2')
            cur.close()
            return render_template('vendor_login.html')
    return render_template('vendor_login.html')


# VENDOR HOMEPAGE
@app.route('/vendor-homepage/', methods=['POST', 'GET'])
def vendor_homepage():
    current_date = date.today()
    # categories
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.category")
    categories = cur.fetchall()
    cur.close()

    # vendors
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.vendors WHERE email = '{session['email']}' ORDER BY vendor_id DESC ")
    vendors = cur.fetchone()
    cur.close()

    # offers
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.offers WHERE vendor_name = '{session['f_name']} {session['l_name']}' "
                f"ORDER BY offer_id DESC ")
    available_offers = cur.fetchall()
    cur.close()

    # vendor products
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials")

    if request.method == 'POST':
        # sending to materials table
        vendor_name = request.form['vendor_name']
        vendor_email = request.form['vendor_email']
        crop_name = request.form['crop_type']
        payment_method = request.form['payment_method']
        acc_number = request.form['acc_number']
        phone_no = request.form['phone_no']
        location = request.form['location']
        org_name = request.form['org_name']
        quantity_per_acre = request.form['land_size']
        price_per_kg = request.form['price']
        vendor_crop = f"{vendor_name} {crop_name}"

        vendor_id = request.form['vendor_id']

        # send to materials table
        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.materials(vendor_id, vendor_name, vendor_email, crop_name,"
                    "quantity_per_acre, price_per_kg, payment_method, acc_number, phone_no, location, "
                    "org_name, vendor_crop_counter) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                        vendor_id, vendor_name, vendor_email, crop_name, quantity_per_acre, price_per_kg,
                        payment_method, acc_number,
                        phone_no, location, org_name, vendor_crop
                    ))
        mysql.connection.commit()
        cur.close()
        flash('Submitted successfully to admin, please wait for approval.', 'green lighten-2')
        return redirect(url_for('vendor_home'))
    return render_template('vendor_homepage.html', current_date=current_date, categories=categories, vendors=vendors,
                           available_offers=available_offers)


# VENDOR LOGOUT
@app.route('/vendor-logout/', methods=['POST', 'GET'])
def vendor_logout():
    if 'vendor_id' in session:
        cur = mysql.connection.cursor()
        uid = session['vendor_id']
        f_name = session['f_name']
        l_name = session['l_name']
        x = '0'
        cur.execute("UPDATE habahaba_trial.vendors SET online=%s WHERE vendor_id=%s ", (x, uid))
        cur.close()
        flash(f'You are now logged out {f_name}', 'danger')
        return redirect(url_for('vendor_login'))
    return redirect(url_for('vendor_login'))


# VENDOR OFFERS
# @app.route('/vendor-offers/', methods=['POST', 'GET'])
# def vendor_offers():
#     if request.method == 'POST':
#         vendor_name = request.form['vendor_name']
#         vendor_email = request.form['vendor_email']
#         org_name = request.form['org_name']
#         offer_name = request.form['offer_name']
#         percentage_off = request.form['percentage_off']
#         valid_until = request.form['valid_until']
#
#         cur = mysql.connection.cursor()
#         cur.execute("INSERT INTO habahaba_trial.offers (vendor_name, vendor_email, org_name, offer_name, percentage_off"
#                     ", valid_until) "
#                     "VALUES (%s, %s, %s, %s, %s, %s)", (
#                         vendor_name, vendor_email, org_name, offer_name, percentage_off, valid_until
#                     ))
#         mysql.connection.commit()
#         cur.close()
#         flash('Offer submitted successfully', 'green lighten-2')
#         return redirect(url_for('vendor_homepage'))
#     return render_template('vendor_homepage.html')


# DELETE OFFERS
@app.route('/delete-offer/<string:id_data>', methods=['POST', 'GET'])
def delete_offer(id_data):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM habahaba_trial.offers WHERE offer_id=%s" % id_data)
    mysql.connection.commit()
    cur.close()
    flash('Offer removed successfully', 'orange lighten-1')
    return redirect(url_for('vendor_homepage'))


# VENDOR HOME
@app.route('/vendor-home/', methods=['POST', 'GET'])
def vendor_home():
    # vendor account
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT account_type FROM habahaba_trial.vendors WHERE vendor_id = '{session['vendor_id']}'")
    acc_type = cur.fetchone()
    cur.close()

    # clients
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.partnership WHERE vendor_id = '{session['vendor_id']}' ")
    users = cur.fetchall()
    cur.close()

    # products
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}'")
    products = cur.fetchall()
    cur.close()

    # offers
    names = f"{session['f_name']} {session['l_name']}"
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.offers WHERE vendor_name = '{names}' AND org_name = '{session['org_name']}'")
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


# VENDOR ADD ACCOUNT
@app.route('/add-account/', methods=['POST', 'GET'])
def vendor_add_account():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.vendors WHERE vendor_id = '{session['vendor_id']}' ORDER BY vendor_id ")
    vendor = cur.fetchone()
    cur.close()

    acc_type = 50

    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        gender = request.form.get('gender')
        phone_no = request.form['phone_no']
        id_no = request.form['id_no']
        account_type = request.form.get('account_type')
        location = request.form['location']
        registered_on = request.form['registered_on']
        email = request.form['email']
        password = sha256_crypt.encrypt(str(request.form['password']))

        commission = vendor['commission']
        payment_method = vendor['payment_method']
        acc_number = vendor['acc_number']
        org_name = vendor['org_name']
        general_industry = vendor['general_industry']
        acc_status = 'set_up'

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.vendors (f_name, l_name, gender, phone_no, commission, id_no, "
                    "payment_method, org_name, location, registered_on, acc_number, acc_status, general_industry,"
                    " email, passwords, account_type) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                        f_name, l_name, gender, phone_no, commission, id_no, payment_method, org_name, location,
                        registered_on, acc_number, acc_status, general_industry, email, password, account_type
                    ))
        mysql.connection.commit()
        cur.close()

        flash("New account added successfully", "success")
        return redirect(url_for('vendor_add_account'))
    return render_template('vendor_add_account.html', acc_type=acc_type)


# VENDOR PRODUCT VERIFICATION
@app.route('/vendor-product-registration/', methods=['POST', 'GET'])
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

        regions = request.form.getlist('region')
        region = ','.join(regions)

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
        except:
            flash('Product already exists', 'danger')
            return redirect(url_for('vendor_product_verification'))
    return render_template('vendor_product_verification.html', categories=categories)


# VENDOR LIST
@app.route('/client-list/', methods=['POST', 'GET'])
def vendor_partners():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.partnership WHERE vendor_id = '{session['vendor_id']}'")
    partners = cur.fetchall()
    cur.close()
    return render_template('vendor-partners.html', partners=partners)


# VENDOR CLIENT ONBOARDING
@app.route('/client-registration/', methods=['POST', 'GET'])
def vendor_user_onboarding():
    password_pin = random.randint(1000, 9999)
    password = str(password_pin)
    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        gender = request.form.get('gender')
        # dob = request.form['dob']
        phone_no = request.form['phone_no']
        id_no = request.form['id_no']
        email = request.form['email']
        # password = sha256_crypt.encrypt(str(request.form['password']))
        # password = request.form['password']
        passwords = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.users (f_name, l_name, gender, phone_no, id_no, email,"
                        " password) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
                        (f_name, l_name, gender, phone_no, id_no, email, passwords))
            mysql.connection.commit()
            cur.close()

            # headers = {
            #     "Content-Type": "application/json"
            #     # "Authorization": f"Bearer {ac_token()}"
            # }
            # payload = {
            #     "apikey": "1d0bda2feac539bfb5042d00440a0877",
            #     "partnerID": 196,
            #     'pass_type': "plain",
            #     "shortcode": "MZAWADI",
            #     "mobile": phone_no,
            #     "message": f"Your password is {password}.Go to www.habahaba.com and log in with your phone"
            #                f" number and password to see more",
            # }
            # my_res = requests.request("POST", "https://quicksms.advantasms.com/api/services/sendsms/",
            #                           headers=headers, json=payload)
            text_msg(phone_no, password)
            flash('User added successfully', 'success')
            return redirect(url_for('vendor_user_onboarding'))
        except (MySQLdb.Error, MySQLdb.Warning) as e:
            flash('This email already exists, please try another one', 'danger')
            return redirect(url_for('vendor_user_onboarding'))
    return render_template('vendor_user_onboarding.html')


# VENDOR OFFER LIST
@app.route('/vendor-offer-list/', methods=['POST', 'GET'])
def vendor_offer_list():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.offers WHERE vendor_email = '{session['email']}' ORDER BY offer_id DESC ")
    offers = cur.fetchall()
    cur.close()
    return render_template('vendor-offers.html', offers=offers)


# VENDOR CHARTS
@app.route('/vendor-chart/', methods=['POST', 'GET'])
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
def vendor_mass_onboarding():
    if request.method == 'POST':
        csv_file = request.files['csv_file']
        return redirect(url_for('vendor_user_onboarding'))
    # return render_template('vendor_mass_onboarding.html')


# VENDOR CLIENT LIST
@app.route('/client-list/')
def client_list():
    # all a member's clients
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.partnership WHERE vendor_id = '{session['vendor_id']}' ")
    users = cur.fetchall()
    cur.close()
    return render_template('vendor_client_list.html', users=users)


# VENDOR PRODUCTS
@app.route('/vendor-products/', methods=['POST', 'GET'])
def vendor_products():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}' AND material_status = 'accepted' ")
    products = cur.fetchall()
    cur.close()
    return render_template('vendor-products.html', products=products)


# DELETE VENDOR PRODUCTS
@app.route('/vendor-delete-products', methods=['POST'])
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
@app.route('/vendor-offer/', methods=['POST', 'GET'])
def vendors_offer_list():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}'")
    products = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.offers WHERE vendor_email = '{session['email']}' AND offer_status = 'accepted'")
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

        region_available = request.form.getlist('region_available')
        region = ','.join(region_available)

        offer_status = 'Pending'

        if region == '':
            flash('Please select a region where your offer will be available', 'warning')
            return redirect(url_for('vendors_offer_list'))

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.offers (vendor_name, vendor_email, org_name, offer_name, percentage_off"
                    ", valid_until, region_available, active_from, offer_status) "
                    "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)", (
                        vendor_name, vendor_email, org_name, offer_name, percentage_off, valid_until, region, today,
                        offer_status
                    ))
        mysql.connection.commit()
        cur.close()
        flash('Offer submitted successfully', 'success')
        return redirect(url_for('vendors_offer_list'))
    return render_template('vendors-offers.html', products=products, offers=offers, counties=counties)


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[JSON FILES]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
# vendor-jsons
@app.route('/transactions-json/', methods=['POST', 'GET'])
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
def client_list_json():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT client_name, client_email, client_phone, vendor_crop"
                f" FROM habahaba_trial.partnership WHERE vendor_id = '{session['vendor_id']}' ")
    users = cur.fetchall()
    cur.close()
    return datatable(users)


@app.route('/vendor-partners-json/', methods=['GET'])
def vendor_partners_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT client_name, client_email, client_phone, vendor_crop FROM habahaba_trial.partnership"
        f" WHERE vendor_id = '{session['vendor_id']}'")
    partners = cur.fetchall()
    cur.close()
    return datatable(partners)


@app.route('/vendor-user-transactions-json/', methods=['GET'])
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
def vendor_products_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT material_id, crop_name, quantity_per_acre, price_per_kg FROM "
        f"habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}' AND material_status = 'accepted' "
        f"ORDER BY material_id DESC ")
    products = cur.fetchall()
    cur.close()
    return datatable(products)


@app.route('/admin-view-vendor-products-json/', methods=['GET', 'POST'])
def admin_view_vendor_products_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT material_id, org_name, crop_name, location, quantity_per_acre, price_per_kg, "
        "material_status  FROM habahaba_trial.materials")
    materials = cur.fetchall()
    cur.close()
    return datatable(materials)


@app.route('/admin-categories-json/', methods=['GET'])
def admin_categories_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT category_id, category_name, sub_category FROM habahaba_trial.category")
    categories = cur.fetchall()
    cur.close()
    return datatable(categories)


# @app.route('/admin-view-farmers-json/', methods=['GET', 'POST'])
# def admin_view_farmers_json():
#     cur = mysql.connection.cursor()
#     cur.execute(
#         "SELECT material_id, org_name, crop_name, location, quantity_per_acre, price_per_kg, "
#         "material_status  FROM habahaba_trial.materials")
#     materials = cur.fetchall()
#     cur.close()
#     return datatable(materials)


@app.route('/user-transactions-json/', methods=['GET'])
def user_transactions_json():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT sender_name, sender_email, sender_phone, amount_sent, saving_target, date_sent"
                f" FROM habahaba_trial.payment_transactions WHERE vendor_id = '{session['vendor_id']}'")
    transactions = cur.fetchall()
    cur.close()
    return datatable(transactions)


@app.route('/vendor-offer-list-json/', methods=['GET'])
def vendor_offer_list_json():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT offer_name, percentage_off, valid_until, offer_status "
        f"FROM habahaba_trial.offers WHERE vendor_email = '{session['email']}' ORDER BY offer_id DESC ")
    offers = cur.fetchall()
    cur.close()
    return datatable(offers)


@app.route('/counties-json/', methods=['POST', 'GET'])
def counties_json():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.counties")
    counties = cur.fetchall()
    cur.close()
    return json.dumps(counties)


@app.route('/vendors-home-json/', methods=['POST', 'GET'])
def vendor_home_json():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.vendors WHERE vendor_id = '{session['vendor_id']}'")
    vendor = cur.fetchone()
    cur.close()
    return json.dumps(vendor)


@app.route('/products-json/', methods=['POST', 'GET'])
def products_json():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.materials WHERE vendor_id = '{session['vendor_id']}'")
    products = cur.fetchall()
    cur.close()
    return json.dumps(products)


@app.route('/chart-json/', methods=['POST', 'GET'])
def chart_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT sender_name, sender_phone, amount_sent, org_name FROM habahaba_trial.payments_table")
    items = cur.fetchall()
    cur.close()
    return json.dumps(items)


@app.route('/view-users-json/', methods=['GET'])
def view_users_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT f_name, l_name, gender, phone_no, id_no FROM habahaba_trial.users")
    users = cur.fetchall()
    cur.close()
    return datatable(users)


@app.route('/admin-view-offers-json/', methods=['GET'])
def admin_view_offers_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT org_name, offer_name, percentage_off, valid_until, region_available"
                " FROM habahaba_trial.offers WHERE offer_status = 'accepted'")
    offers = cur.fetchall()
    cur.close()
    return datatable(offers)


@app.route('/user-vendor-json/', methods=['GET'])
def user_vendor_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT f_name, l_name, gender, phone_no, id_no, email FROM habahaba_trial.users")
    users = cur.fetchall()
    cur.close()


@app.route('/admin-vendors-json/', methods=['POST', 'GET'])
def admin_view_vendors_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT vendor_id, org_name, location, email, commission,"
        " payment_method, acc_number"
        " FROM habahaba_trial.vendors")
    vendors = cur.fetchall()
    cur.close()
    return datatable(vendors)


@app.route('/view-vendors-json/', methods=['POST', 'GET'])
def view_vendors_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT * FROM habahaba_trial.vendors")
    vendors = cur.fetchall()
    cur.close()
    return json.dumps(vendors)


@app.route('/admin-view-products-json/', methods=['GET'])
def admin_view_products_json():
    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT org_name, crop_name, quantity_per_acre, price_per_kg, region"
        " FROM habahaba_trial.materials WHERE material_status = 'accepted'")
    products = cur.fetchall()
    cur.close()
    return datatable(products)


@app.route('/admin-action-offers-json/', methods=['GET'])
def admin_action_offers_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT offer_id, org_name, offer_name, percentage_off, valid_until, offer_status"
                " FROM habahaba_trial.offers ORDER BY offer_id DESC")
    offers = cur.fetchall()
    cur.close()
    return datatable(offers)


@app.route('/vendor-json/', methods=['POST'])
def vendors_json():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.vendors")
    vendors = cur.fetchall()
    cur.close()
    return json.dumps(vendors)


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
@app.route('/client-onboarding/', methods=['POST', 'GET'])
def client_onboarding():
    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        gender = request.form.get('gender')
        dob = request.form['dob']
        phone_no = request.form['phone_no']
        id_no = request.form['id_no']
        email = request.form['email']
        password = sha256_crypt.encrypt(str(request.form['password']))

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.users (f_name, l_name, gender, dob, phone_no, id_no, email,"
                        " password) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (f_name, l_name, gender, dob, phone_no, id_no, email, password))
            mysql.connection.commit()
            cur.close()
            flash('User added successfully', 'success')
            return redirect(url_for('client_onboarding'))
        except:
            flash('This email already exists, please try another one', 'warning')
            return redirect(url_for('client_onboarding'))
    return render_template('client_onboarding.html')


@app.route('/example/', methods=['POST', 'GET'])
def example():
    return render_template('example.html')


@app.route('/user-registration/', methods=['POST', 'GET'])
def user_registration():
    if request.method == 'POST':
        f_name = request.form['f_name']
        l_name = request.form['l_name']
        gender = request.form.get('gender')
        dob = request.form['dob']
        phone_no = request.form['phone_no']
        id_no = request.form['id_no']
        email = request.form['email']
        password = sha256_crypt.encrypt(str(request.form['password']))

        try:
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.users (f_name, l_name, gender, dob, phone_no, id_no, email,"
                        " password) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (f_name, l_name, gender, dob, id_no, phone_no, email, password))
            mysql.connection.commit()
            cur.close()
            flash('User added successfully', 'green lighten-4')
            return redirect(url_for('user_login'))
        except:
            flash('This user already exists', 'red lighten-2')
            return redirect(url_for('user_registration'))
    return render_template('user_registration.html')


# @app.route('/user-login/', methods=['POST', 'GET'])
@app.route('/', methods=['POST', 'GET'])
def user_login():
    if request.method == 'POST':
        phone_no = request.form['phone_no']
        password_candidate = request.form['password']

        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM habahaba_trial.users WHERE phone_no=%s", [phone_no])

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

                cur.execute("UPDATE habahaba_trial.users SET online=%s WHERE user_id=%s", (x, uid))
                return redirect(url_for('user_homepage'))
            else:
                flash('Incorrect password, please try again', 'red lighten-2')
                return render_template('user_login.html')
        else:
            flash('This email is not registered', 'red lighten-2')
            cur.close()
            return render_template('user_login.html')
    return render_template('user_login.html')


@app.route('/change-password/', methods=['POST', 'GET'])
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
        flash(f'You are now logged out {f_name}', 'red lighten-2')
        return redirect(url_for('user_login'))
    return redirect(url_for('user_login'))


@app.route('/user-homepage/', methods=['POST', 'GET'])
def user_homepage():
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.ukulima WHERE holder_email = '{session['email']}'")
    holder = cur.fetchall()
    cur.close()
    # Activate card
    if request.method == 'POST':
        wallet_holder = request.form['wallet_holder']
        email = request.form['holder_email']
        balance = request.form['balance']
        spent = request.form['spent']
        deposited = request.form['deposited']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.ukulima (wallet_holder, holder_email, balance, spent, deposited)"
                    " VALUES (%s, %s, %s, %s, %s)",
                    (wallet_holder, email, balance, spent, deposited))
        mysql.connection.commit()
        cur.close()
        flash('Card activated successfully', 'green lighten-2')
        return redirect(url_for('habahaba_ukulima'))
    return render_template('user_homepage.html', holder=holder)


@app.route('/habahaba_ukulima/', methods=['POST', 'GET'])
def habahaba_ukulima():
    # get specified account balance
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT balance FROM habahaba_trial.ukulima WHERE holder_email = '{session['email']}'")
    balance = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        wallet_holder = request.form['wallet_holder']
        holder_email = request.form['holder_email']
        target = request.form['target']
        save_until = request.form['save_until']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.targets (wallet_holder, holder_email, target, save_until) "
                    "VALUES (%s, %s, %s, %s)",
                    (wallet_holder, holder_email, target, save_until))
        mysql.connection.commit()
        cur.close()
        return redirect(url_for('habahaba_ukulima'))
    return render_template('habahaba_ukulima.html', balance=balance)


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[service worker registration]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
@app.route('/sw.js', methods=['GET'])
def sw():
    return current_app.send_static_file('sw.js')


# CLIENT LOGIN
@app.route('/login/')
def index():
    return render_template('login.html')


@app.route('/ukulima/', methods=['POST', 'GET'])
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
        except:
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


@app.route('/ukulima-targets/', methods=['POST', 'GET'])
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
def partner_details():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials")
    vendor_materials = cur.fetchall()
    return json.dumps(vendor_materials)


@app.route('/remove-partner/<string:id_data>', methods=['POST', 'GET'])
def remove_partner(id_data):
    cur = mysql.connection.cursor()
    cur.execute("DELETE FROM habahaba_trial.partnership WHERE partnership_id=%s" % id_data)
    mysql.connection.commit()
    cur.close()
    flash('Partner removed successfully', 'green lighten-2')
    return redirect(url_for('targets'))


@app.route('/partner-options/', methods=['POST', 'GET'])
def partner_options():
    cur = mysql.connection.cursor()
    cur.execute('SELECT * FROM habahaba_trial.materials')
    partners = cur.fetchall()
    cur.close()
    return json.dumps(partners)


@app.route('/ukulima-target/', methods=['POST', 'GET'])
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
        "materials.phone_no, email, price_per_kg FROM habahaba_trial.materials INNER JOIN "
        "habahaba_trial.vendors ON vendor_email=email")
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
def ukulima_profile():
    return jsonify({"crops": ["maize", "beans"]})


@app.route('/testing/', methods=['POST', 'GET'])
def testing():
    vender_id = request.form.get('profile')

    cur = mysql.connection.cursor()
    cur.execute(
        "SELECT vendor_name, vendor_email, crop_name, materials.payment_method, materials.acc_number, "
        "materials.phone_no, email, price_per_kg FROM habahaba_trial.materials INNER JOIN "
        "habahaba_trial.vendors ON vendor_email=email")
    results = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials ORDER BY material_id ")
    test_json = cur.fetchall()
    cur.close()
    json_var = f"{json.dumps(test_json)}"
    return json.dumps(results)


@app.route('/ukulima-offers/', methods=['POST', 'GET'])
def ukulima_offers():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.offers ORDER BY offer_id DESC ")
    available_offers = cur.fetchall()
    cur.close()

    var = mysql.connection.cursor()
    var.execute("SELECT count(*) FROM habahaba_trial.offers WHERE offer_status = 'accepted'")
    total_rows = var.fetchall()
    var.close()
    return render_template('ukulima_offers.html', available_offers=available_offers, total_rows=total_rows)


@app.route('/ukulima-partners/', methods=['POST', 'GET'])
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
def vendor_goods():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.redirecting_table ORDER BY redirect_id DESC")
    vendor_org = cur.fetchone()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.materials WHERE org_name = '{vendor_org['vendor_org']}'")
    vendors = cur.fetchall()
    cur.close()
    return render_template('vendor_goods.html', vendors=vendors, vendor_org=vendor_org)


# all goods from JSON
@app.route('/all_goods/', methods=['POST', 'GET'])
def all_goods():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.materials")
    goods = cur.fetchall()
    cur.close()
    return json.dumps(goods)


@app.route('/selected-partner-redirect/', methods=['POST', 'GET'])
def selected_partner_redirect():
    if request.method == 'POST':
        user_id = request.form['user_id']
        material_id = request.form['material_id']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.selected_partner_redirect (user_id, material_id) "
                    "VALUES (%s, %s)", (user_id, material_id))
        mysql.connection.commit()
        cur.close()
    return redirect(url_for('selected_partner'))


# sends the selected vendor's material id to be opened in another page
@app.route('/selected-partner/', methods=['POST', 'GET'])
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
                        "client_name, client_email, client_phone, counter_column, saving_target, save_until) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,%s, %s, %s)",
                        (
                            vendor_id, vendor_name, vendor_email, vendor_phone, vendor_org, crop_name,
                            location, payment_method, acc_number, client_id, client_name, client_email,
                            client_phone, counter_column, saving_target, save_until
                        ))
            mysql.connection.commit()
            cur.close()

            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.payments_table (vendor_id, vendor_name, vendor_email,"
                        "vendor_phone, org_name, sender_id, sender_name, sender_email, "
                        "sender_phone, amount_sent, date_sent, time_sent, date_and_time, saving_target,"
                        " payment_for, client_vendor_crop, quantity_per_acre, price_per_kg, redeemable_amount) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ", (
                            vendor_id, vendor_name, vendor_email, vendor_phone, vendor_org,
                            client_id, client_name, client_email, client_phone, amount, today, now, right_now,
                            saving_target, crop_name, client_vendor_crop, quantity_per_acre, price_per_kg, amount
                        ))
            mysql.connection.commit()
            cur.close()
            flash(f'{crop_name} Partner selected', 'green lighten-2')
            return redirect(url_for('ukulima_partners'))
        except:
            flash(f'You have already selected {vendor_name} for {crop_name}. Please select another partner ',
                  'red lighten-2')
            return redirect(url_for('ukulima_partners'))

        # return redirect(url_for('ukulima_partners'))
    return render_template('selected_partner_onboard.html', vendor_details=vendor_details, client=client)


@app.route('/ukulima-transactions/', methods=['POST', 'GET'])
def ukulima_transactions():
    # amount deposited
    cur = mysql.connection.cursor()
    cur.execute(f"SELECT * FROM habahaba_trial.payment_transactions WHERE sender_id = '{session['user_id']}' ")
    transactions = cur.fetchall()
    cur.close()
    return render_template('ukulima_transactions.html', transactions=transactions)


@app.route('/redemption/', methods=['POST', 'GET'])
def redemption():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}' ORDER BY payment_id DESC ")
    redeemable_items = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        redeemable_amount = request.form['redeemable_amount']
        payment_id = request.form['payment_id']
        quantity_redeemed = request.form['redeem']
        price_per_kg = request.form['price_per_kg']

        cur = mysql.connection.cursor()
        cur.execute(f"SELECT * FROM habahaba_trial.payments_table WHERE payment_id = '{payment_id}'")
        redeemable = cur.fetchone()
        cur.close()

        amount_redeemed = int(quantity_redeemed) * int(price_per_kg)
        redeemable_amounts = (int(redeemable['redeemable_amount']) -
                              (int(quantity_redeemed) * int(redeemable['price_per_kg'])))

        if redeemable_amounts > int(redeemable['redeemable_amount']):
            flash('The value you entered is more than what you can redeem', 'red lighten-2')
            return redirect(url_for('redemption'))

        cur = mysql.connection.cursor()
        cur.execute(
            f""" 
                UPDATE habahaba_trial.payments_table 
                SET quantity_redeemed = %s, amount_redeemed = %s, redeemable_amount = %s
                WHERE payment_id = %s
            """, (
                quantity_redeemed, amount_redeemed, redeemable_amounts, payment_id
            )
        )
        mysql.connection.commit()
        cur.close()

        flash(f'{quantity_redeemed} KGs redeemed successfully', 'green lighten-2')
        return redirect(url_for('redemption'))
    return render_template('ukulima_redemption.html', redeemable_items=redeemable_items)


@app.route('/ukulima-funds/', methods=['POST', 'GET'])
def ukulima_funds():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id= '{session['user_id']}' ORDER BY payment_id DESC ")
    partners = cur.fetchall()
    cur.close()

    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT amount_sent FROM habahaba_trial.payments_table WHERE sender_id = '{session['user_id']}' ORDER BY payment_id DESC ")
    previous_value = cur.fetchone()
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
        vendor_email = request.form['vendor_email']
        vendor_phone = request.form['vendor_phone']
        vendor_org = request.form['vendor_org']
        vendor_crop = request.form['vendor_crop']

        crop_name = request.form['payment_for']

        saving_target = request.form['saving_target']
        amount_sent = request.form['amount_sent']

        # client details
        payment_id = request.form['payment_id']
        client_id = request.form['client_id']
        client_name = request.form['client_name']
        client_email = request.form['client_email']
        client_phone = request.form['client_phone']
        value_entered = request.form['amount']
        amount = int(value_entered) + int(previous_value['amount_sent'])

        client_vendor_crop = f"{vendor_id} {client_id} {vendor_crop}"
        date_counter = f"{this_month} {this_year}"

        if float(value_entered) > (float(saving_target) - float(amount_sent)):
            flash('Amount entered surpasses the target', 'orange lighten-2 white-text')
            return redirect(url_for('ukulima_funds'))
        else:
            # add payment to transaction table
            cur = mysql.connection.cursor()
            cur.execute("INSERT INTO habahaba_trial.payment_transactions (vendor_id, vendor_name, vendor_email,"
                        "vendor_phone, org_name, sender_id, sender_name, sender_email, "
                        "sender_phone, amount_sent, date_sent, time_sent, date_and_time, saving_target,"
                        " payment_for, date_counter) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) ", (
                            vendor_id, vendor_name, vendor_email, vendor_phone, vendor_org, client_id, client_name,
                            client_email, client_phone, amount, today, now, right_now, saving_target,
                            crop_name, date_counter
                        ))
            mysql.connection.commit()
            cur.close()

            # fetching the redeemable amount
            cur = mysql.connection.cursor()
            cur.execute(f"SELECT * FROM habahaba_trial.payments_table WHERE payment_id = '{payment_id}' ")
            redeemable = cur.fetchone()
            cur.close()

            redeemable_amount = int(value_entered) + int(redeemable['redeemable_amount'])

            # update the payments table
            cur = mysql.connection.cursor()
            cur.execute(f"""
            UPDATE habahaba_trial.payments_table
            SET amount_sent = %s, date_sent = %s, time_sent = %s, date_and_time = %s, redeemable_amount = %s
            WHERE payment_id = %s
            """,
                        (amount, today, now, right_now, redeemable_amount, payment_id))
            mysql.connection.commit()
            cur.close()
            flash('Amount sent successfully', 'green lighten-2 white-text')
            return redirect(url_for('ukulima_funds'))
    return render_template('ukulima_funds.html', partners=partners, this_month=this_month, this_year=this_year)


@app.route('/funds-testing/', methods=['POST', 'GET'])
def funds_testing():
    cur = mysql.connection.cursor()
    cur.execute(
        f"SELECT * FROM habahaba_trial.payments_table WHERE sender_id= '{session['user_id']}' ORDER BY payment_id DESC ")
    partners = cur.fetchall()
    cur.close()
    return json.dumps(partners)


@app.route('/get_offers', methods=['GET'])
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


@app.route('/validate-offers/', methods=['POST', 'GET'])
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


@app.route('/vendor-onboarding/', methods=['POST', 'GET'])
def vendor_onboarding():
    today = datetime.today()

    if request.method == 'POST':
        general_industry = request.form['general_industry']
        org_name = request.form['org_name']
        email = request.form['email']
        password = sha256_crypt.encrypt(str(request.form['password']))
        acc_status = 'pending'
        acc_type = 0

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO habahaba_trial.vendors ( org_name, general_industry, acc_status, email, passwords,"
                    "account_type) "
                    "VALUES (%s, %s, %s, %s, %s, %s)", (
                        org_name, general_industry, acc_status, email, password, acc_type
                    ))
        mysql.connection.commit()
        cur.close()
        flash("Partner added successfully. Please setup the vendor at Vendor Setup", "success")
        return redirect(url_for('vendor_onboarding'))
    return render_template('admin_onboard_vendors.html', today=today)


@app.route('/redemption-orders/', methods=['POST', 'GET'])
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
    cur.execute("SELECT * FROM habahaba_trial.payment_transactions")
    transactions = cur.fetchall()
    cur.close()
    return render_template('test_chart.html', transactions=transactions)


# [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[MPESA DARAJA API]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]
consumer_key = 'AJhUyehvuTGoiANeIo8qW1hNPKdA10kS'
consumer_secret = 'BzMPjAd4yKr97xhv'
base_url = 'http://197.232.79.73:801'


@app.route('/token/', methods=['POST', 'GET'])
def tokens():
    data = ac_token()
    return data


def ac_token():
    mpesa_auth_url = 'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials'
    data = (requests.get(mpesa_auth_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))).json()
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
    # return json.dumps(response_data)


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
        #     "Password": "MTc0Mzc5YmZiMjc5ZjlhYTliZGJjZjE1OGU5N2RkNzFhNDY3Y2QyZTBjODkzMDU5YjEwZjc4ZTZiNzJhZGExZWQyYzkxOTIwMjIxMTI0MDk0NDE5",
        #     "Timestamp": "20221128114319",
        #     "TransactionType": "CustomerPayBillOnline",
        #     "Amount": amount,
        #     "PartyA": phone,
        #     "PartyB": 174379,
        #     "PhoneNumber": phone,
        #     "CallBackURL": my_endpoint + "/callback/",
        #     "AccountReference": "CompanyXLTD",
        #     "TransactionDesc": "Payment of X",
        # }

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
        cur = mysql.connection.cursor()
        for this_name in names:
            # print(this_name.rstrip())
            cur.execute("INSERT INTO habahaba_trial.names (f_names, gender) VALUES (%s, %s) ", (
                this_name[0:], this_name[0:]
            ))
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
        "message": f"Use the username {phone_no} and password {password} to login to www.habahaba.com",
    }
    my_res = requests.request("POST", "https://quicksms.advantasms.com/api/services/sendsms/",
                              headers=headers, json=payload)

    return my_res.json()


if __name__ == '__main__':
    app.run(debug=True, port=5000)

# LEARN JWT
