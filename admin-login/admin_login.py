from app import *


@app.route('/zzz/', methods=['POST', 'GET'])
def admin_view_offers():
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM habahaba_trial.offers WHERE offer_status = 'accepted'")
    offers = cur.fetchall()
    cur.close()
    # return render_template('admin_view_offers.html', offers=offers)
    return render_template('../templates/admin_view_offers.html', offers=offers)
