from flask import Flask, render_template, request, session, redirect
from datetime import datetime, timedelta
from threading import Thread
import pyotp
import json
import http.client
import mimetypes
import time


app = Flask(__name__)
app.secret_key = "your_secret_key"
conn = http.client.HTTPSConnection("apiconnect.angelbroking.com")


def five_min(header, date_str, time_str):

    date_str = date_str.strftime("%Y-%m-%d")
    time_str = time_str.strftime("%H:%M")

    payload = {
        "exchange": "NSE",
        "symboltoken": "99926000",
        "interval": "FIVE_MINUTE",
        "fromdate":  date_str+' 09:15',
        "todate": date_str+' '+time_str
    }
    payload_str = json.dumps(payload)

    conn.request("POST", "/rest/secure/angelbroking/historical/v1/getCandleData", payload_str, header)
    res = conn.getresponse()
    data = res.read().decode("utf-8")
    conn.close()
    data_dict = json.loads(data)
    candle_data = data_dict['data']
    return candle_data



def algo_five(candle_data):
    if len(candle_data) < 5:
        return False

    last_candle = candle_data[-1]
    second_last_candle = candle_data[-2]
    third_last_candle = candle_data[-3]
    fourth_last_candle = candle_data[-4]
    fifth_last_candle = candle_data[-5]
    mini = min(third_last_candle[4], second_last_candle[4], fourth_last_candle[4])
    print(f" 1st {last_candle[1]} 2nd {second_last_candle[2]} 3rd {third_last_candle[3]}")
    if (last_candle[4] < last_candle[1] and
            second_last_candle[4] < second_last_candle[1] and
            third_last_candle[4] < third_last_candle[1] and
            fourth_last_candle[4] < fourth_last_candle[1] and
            second_last_candle[2] > third_last_candle[1] and
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


def order_check(headers):
    date_str = datetime.now() 
    time_str = datetime.strptime("15:30", "%H:%M")
    candle_data = five_min(headers, date_str, time_str)
    order_placed = algo_five(candle_data)
    if order_placed:
        return True, candle_data
    else:
        return False, candle_data


@app.route('/profile', methods=['POST', 'GET'])
def profile():
    if 'user' in session:
        user = session['user']
        if request.method == 'POST':
            date_str = request.form['date_str']
            time_str = request.form['time_str']
            date_str = datetime.strptime(date_str, "%Y-%m-%d")
            time_str = datetime.strptime(time_str, "%H:%M")
            holdings = five_min(user['headers'], date_str, time_str)
            order_placed = algo_five(holdings)
            if order_placed:
                return redirect('/order')
            else:
                order_placed = "Do not place the order"
                return render_template('profile.html', name=order_placed, holdings=holdings)
        else:
            result, candle_data = order_check(user['headers'])
            if result:
                return redirect('/order')
            else:
                order_st = "Do not place the order yet"
            return render_template('profile.html', name=order_st, holdings=candle_data)
    return "Please login first"


@app.route('/check')
def check():
    if 'user' in session:
        user = session['user']
        return render_template('check.html')
    else:
        return render_template('index.html')


@app.route('/status')
def get_status():
    if 'user' in session:
        user = session['user']
        result, candle_data = order_check(user['headers'])
        if result:
            return 'true'
        else:
            return str(candle_data[-1][-2])
    else:
        return str("Login Your Account")

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

@app.route('/reset')
def reset():
    if 'user' in session:
        pass

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0', debug=True)
