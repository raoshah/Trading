from flask import Flask, render_template, request, session, redirect
from datetime import datetime, timedelta
import pyotp
import json
import http.client
import mimetypes
import time

app = Flask(__name__)
app.secret_key = "your_secret_key"
conn = http.client.HTTPSConnection("apiconnect.angelbroking.com")

def five_min_candle(header, six_days_ago):

    candle_data_list = []
    print(six_days_ago)
    for i in range(5):
        from_date = six_days_ago - timedelta(minutes=5 * (i + 1))
        to_date = six_days_ago - timedelta(minutes=5 * i)
        from_date_str = from_date.strftime("%Y-%m-%d %H:%M")
        to_date_str = to_date.strftime("%Y-%m-%d %H:%M")

        payload = {
            "exchange": "NSE",
            "symboltoken": "99926000",
            "interval": "FIVE_MINUTE",
            "fromdate": from_date_str,
            "todate": to_date_str
        }
        payload_str = json.dumps(payload)

        conn.request("POST", "/rest/secure/angelbroking/historical/v1/getCandleData", payload_str, header)
        res = conn.getresponse()
        data = res.read().decode("utf-8")
        candle_data_list.append(data)
        time.sleep(0.2)
        conn.close()

    specific_data_list = []

    for json_data in candle_data_list:
        data = json.loads(json_data)
        specific_data = data['data'][1]
        specific_data_list.append(specific_data)

    return specific_data_list

def algo_five(candle_data):
    if len(candle_data) < 5:
        return False

    last_candle = candle_data[0]
    second_last_candle = candle_data[1]
    third_last_candle = candle_data[2]
    fourth_last_candle = candle_data[3]
    fifth_last_candle = candle_data[4]
    mini = min(third_last_candle[4], second_last_candle[4], fourth_last_candle[4])

    if (last_candle[4] < last_candle[1] and
            second_last_candle[4] < second_last_candle[1] and
            third_last_candle[4] < third_last_candle[1] and
            fourth_last_candle[4] < fourth_last_candle[1] and
            second_last_candle[2] < third_last_candle[1] and
            last_candle[4] < mini):
        return True
    else:
        return False



@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=["POST", "GET"])
def login():
    if request.method == "POST":
        client = request.form["client_id"]
        tpin = request.form["tpin"]
        otp = request.form["otp"]
        api = request.form["apikey"]
        token = pyotp.TOTP(otp).now()
        payload = {
            "clientcode": client,
            "password": tpin,
            "totp": token
        }

        payload_str = json.dumps(payload)

        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'X-UserType': 'USER',
            'X-SourceID': 'WEB',
            'X-ClientLocalIP': 'CLIENT_LOCAL_IP',
            'X-ClientPublicIP': 'CLIENT_PUBLIC_IP',
            'X-MACAddress': 'MAC_ADDRESS',
            'X-PrivateKey': api
        }

        conn.request("POST", "/rest/auth/angelbroking/user/v1/loginByPassword", payload_str, headers)
        res = conn.getresponse()
        data = res.read()
        response_json = json.loads(data.decode("utf-8"))
        jwt_token = response_json['data']['jwtToken']
        conn.close()
        headers = {
        'Authorization': 'Bearer '+jwt_token,
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        'X-UserType': 'USER',
        'X-SourceID': 'WEB',
        'X-ClientLocalIP': 'CLIENT_LOCAL_IP',
        'X-ClientPublicIP': 'CLIENT_PUBLIC_IP',
        'X-MACAddress': 'MAC_ADDRESS',
        'X-PrivateKey': api
        }
        session['user'] = {
            'headers': headers,
            'api': api,
            'token': jwt_token
        }
        print(session)
        return redirect('/profile')
    return render_template('index.html')

@app.route('/profile', methods=['POST', 'GET'])
def profile():
    if 'user' in session:
        user = session['user']
        userProfile = user
        if request.method == 'POST':
            six_days_ago = request.form['dateTime']
            six_days_ago = datetime.strptime(six_days_ago, "%Y-%m-%d %H:%M:%S")
            holdings = five_min_candle(user['headers'], six_days_ago)
            order_placed = algo_five(holdings)
            if order_placed:
                return redirect('/order')
            else:
                order_placed = "Do not place the order"
                return render_template('profile.html', name=order_placed, holdings=holdings)
        else:
            six_days_ago = datetime.now() - timedelta(days=6, hours=11)
            six_days_ago = datetime.strptime(six_days_ago, "%Y-%m-%d %H:%M:%S")
            holdings = five_min_candle(user['headers'], six_days_ago)
            order_placed = algo_five(holdings)
            if order_placed:
                return redirect('/order')
            else:
                order_placed = "Do not place the order"
            return render_template('profile.html', name=order_placed, holdings=holdings)
    return "Please login first"

@app.route('/order')
def order():
  if 'user' in session:
    user = session['user']
    userProfile = user
    payload = {
        "variety":"NORMAL",
        "tradingsymbol":"SBIN-EQ",
        "symboltoken":"3045",
        "transactiontype":"BUY",
        "exchange":"NSE",
        "ordertype":"MARKET",
        "producttype":"INTRADAY",
        "duration":"DAY",
        "price":"194.50",
        "squareoff":"0",
        "stoploss":"0",
        "quantity":"1"
        }
    payload_str = json.dumps(payload)
    conn.request("POST","/rest/secure/angelbroking/order/v1/placeOrder",payload_str,user['headers'])
    res = conn.getresponse()
    data = res.read()
    print(data.decode("utf-8"))
    conn.close()
    return 'seccuss'
  return "Please login first"


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
