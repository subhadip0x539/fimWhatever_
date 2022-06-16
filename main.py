import hashlib
from flask import Flask, request, jsonify, session
from flask_mongoengine import MongoEngine
from apscheduler.schedulers.background import BackgroundScheduler
import os
import glob
from datetime import datetime
from time import time
from flask_bcrypt import Bcrypt
from flask_session import Session
from functools import wraps
import re
from odd_jobs import compare_db, compare_db_gin, drop_collection, set_analyticsTozero
from verify import scan_baseline, quick_scan
import sys
from AES_CBC import zip
import random
from mongoengine import connect
from requests import get
import json


CONFIG = {
    'port': 5000,
    'host': '0.0.0.0',
    'db_user': os.environ.get("MONGODB_USER"),
    'db_name': os.environ.get("MONGODB_DB_NAME"),
    'db_pass': os.environ.get("MONGODB_PASS"),
    'secret_key': os.environ.get("SECRET_KEY"),
    'buff_size': 65536
}


SETTINGS = {
    'alert': "False",
    "manual": "False",
    "cron": "False",
    "auto_enc": False,
    "interval": 86400,
    "wait": False
}

app = Flask(__name__, static_folder='build', static_url_path='/')
app.config['SECRET_KEY'] = CONFIG['secret_key']
app.config['SESSION_TYPE'] = "filesystem"
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
sess = Session()
sess.init_app(app)
bcrypt = Bcrypt(app)
db_uri = 'mongodb+srv://{}:{}@cluster0.h5jad.mongodb.net/{}?retryWrites=true&w=majority'.format(CONFIG['db_user'], CONFIG['db_pass'], CONFIG['db_name'])
app.config['MONGODB_HOST'] = db_uri
db = MongoEngine()
db.init_app(app)
cron = BackgroundScheduler(daemon=True)
cron.start()



class baseline(db.DynamicDocument):
    pass

class baseline_bak(db.DynamicDocument):
    pass

class syslog(db.DynamicDocument):
    pass

class alertlog(db.DynamicDocument):
    pass

class analytics(db.DynamicDocument):
    pass

class chart(db.DynamicDocument):
    pass

class users(db.DynamicDocument):
    pass

class keys(db.DynamicDocument):
    pass


email_regex = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
pw_regex = r'[A-Za-z0-9@#$%^&+=]{4,}'
id_regex = r'[A-Fa-f0-9]{24}'


@app.route('/')
def index():
    return app.send_static_file('index.html')

@app.errorhandler(404)
def not_found(err):
    return app.send_static_file('index.html')

@app.route('/favicon.ico')
def favicon():    
    return app.send_static_file('favicon.ico')

    
@app.before_first_request
def before_first_request_func():
    try:
        drop_collection([baseline.objects, baseline_bak.objects, analytics.objects, syslog.objects, chart.objects, alertlog.objects])
    finally:   
        analytics(**{'baseline': 0, 'alerts': 0, 'encs': 0, 'scans': 0, 'risk': 0}).save()

def is_working(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if SETTINGS["wait"]:
            return ({"error": "Wait for the baselines to be uploaded"}), 400
        else:
            return f(*args, **kwargs)
    return decorator    

def validate_login(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        req = request.get_json()
        if request:
            if 'email' in req and 'password' in req:
                if re.fullmatch(email_regex, req['email']):
                    return f(req, *args, **kwargs)    
                else:
                    return jsonify({"error": "Invalid email"}), 400
            else:
                return jsonify({"error": "Missing fields"}), 400
    return decorator

def validate_signup(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        req = request.get_json()
        if req:
            error = []
            if 'email' in req and 'password' in req and 'confirm_password' in req:
                if not re.fullmatch(email_regex, req['email']):
                    return jsonify({"error": "Invalid email"}), 400
                    
                if users.objects(email=req['email']):
                    return jsonify({"error": "User already exist with the same email"}), 409    

                if not re.fullmatch(pw_regex, req['password']):
                    return jsonify({"error": "Icorrect password format"}), 400

                if req['password'] != req['confirm_password']:
                    return jsonify({"error": "Passwords do not match"}), 400
                return f(req, *args, **kwargs)
            else:
                return({"error": "Missing fields"}), 400
    return decorator    

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        if 'sess_id' not in session or users.objects(id=session['sess_id']).only('status').first().status != 1:
            return jsonify({"error": "Unauthorized"}), 401
        else:
            return f(*args, **kwargs)    
    return decorator

@app.route('/api2/verifyuserlogin', methods=['GET'])
def post_verifyuserlogin():
    if 'sess_id' in session:
        if users.objects(id=session['sess_id']).only('status').first().status == 1 and users.objects(id=session['sess_id']).only('role').first().role == 'user':
            return({"ack": "authorized"})

        elif users.objects(id=session['sess_id']).only('role').first().role == 'root':
            return jsonify({"error": "Unauthorized"}), 401
    else:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/api2/verifyrootlogin', methods=['GET'])
def post_verifyrootlogin():
    if 'sess_id' in session:
        if [doc['role'] for doc in users.objects(id=session.get('sess_id'))][0] == 'root':
            return jsonify({"ack": "authorized"})
        elif [doc['role'] for doc in users.objects(id=session.get('sess_id'))][0] == 'user':
            return jsonify({"error": "Unauthorized"}), 401
    else:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/api2/signup', methods=['POST'])
@validate_signup
def post_signup(req):
    email = req['email']
    password = req['password']

    pw_hash = bcrypt.generate_password_hash(password)
    user_data = {
        'user': 'Default User',
        'email': email,
        'password': pw_hash.decode(),
        'status': 0,
        'role': 'user'
    }

    users(**user_data).save()

    response = jsonify({"ack": "Sign Up successful, wait for approval"})
    return response

@app.route('/api2/login', methods=['POST'])
@validate_login
def post_login(req):
    email = req['email']
    password = req['password']
    user = users.objects(email=email)
    
    if not user:
        return jsonify({"error": "Incorrect email or password"}), 401
    
    user_data = {}   
    for doc in users.objects(email=email):
        user_data['_id'] = str(doc.id)
        user_data['email'] = doc['email']
        user_data['password'] = doc['password']
        user_data['status'] = doc['status']
        user_data['role'] = doc['role']    
    
    if user_data['status'] == 0:
        return jsonify({"error": "Sign Up approval pending"}), 401
    
    if user_data['status'] == 1:
        if not bcrypt.check_password_hash(user_data['password'], password):
            return jsonify({"error": "Incorrect email or password"}), 401
        session['sess_id'] = user_data['_id']
        lines = open('CVE.txt').read().splitlines()
        myline =random.choice(lines)
        log = open("user_log.txt", "a")
        log.write("{id}\t{role}\t{action}\t{time}\t{email}\n".format(
            id=user_data['_id'], 
            email=user_data['email'], 
            role=user_data['role'], 
            action="login", 
            time=datetime.now().strftime("%d-%b-%Y %H:%M:%S").upper()
            )
        )
        return jsonify({"role": user_data['role'], "cve": myline})

@app.route('/api2/logout', methods=['POST'])
def post_logout():
    log = open("user_log.txt", "a")
    log.write("{id}\t{role}\t{action}\t{time}\t{email}\n".format(
        id=session.get('sess_id'), 
        email=users.objects(id=session.get('sess_id')).only('email').first().email,
        role=users.objects(id=session.get('sess_id')).only('role').first().role,
        action="logout",
        time=datetime.now().strftime("%d-%b-%Y %H:%M:%S").upper()
        )
    )

    session.pop('sess_id')

    return jsonify()

@app.route('/api2/authsignup', methods=['POST'])
@token_required
def post_authsignup():
    req = request.get_json()
    _id = session.get('sess_id')
    user = req['email']
    status = req['status']
    
    if users.objects(id=_id).only('role').first().role == 'root':
        users.objects(email=user).update_one(set__status=status)
        return jsonify({"ack": "User status successfully updated"})
    else:
        return jsonify({"error": "Unauthorized"}), 401

@app.route('/api2/users', methods=['GET'])
@token_required
def get_users():
    _id = session.get('sess_id')
    user_data = []

    if users.objects(id=_id).only('role').first().role != 'root':
        return jsonify({"error": "Unauthorized"}), 401

    for doc in users.objects(role__ne='root'):
        user = {}
        user['email'] = doc['email']
        user['role'] = doc['role']
        user['status'] = doc['status']
        user['user'] = doc['user']
        user_data.append(user)

    return jsonify(user_data)

@app.route('/api2/baseline', methods=['POST'])
@is_working
@token_required
def post_baseline():
    SETTINGS["wait"] = True
    req = request.get_json()
    if not req:
        SETTINGS["wait"] = False
        return jsonify({"error": "Invalid input"}), 400
    if not req['paths']:
        SETTINGS["wait"] = False
        return jsonify({"error": "Invalid input"}), 400

    paths = req['paths']
    base = []
    files = []
    dirs = []

    for path in paths:
        if os.path.isfile(path):
            base.append(path)
        elif os.path.isdir(path):
            for dirName, subdirList, fileList in os.walk(path):
                for file in glob.glob(os.path.join(dirName, '*')):
                    if os.path.isfile(file):
                        base.append(file)
        else:
            SETTINGS["wait"] = False
            return jsonify({"error": "Invalid file or directory"}), 400
    base = list(set(base))                
    
    for file in base:
        f = open(file, 'rb')
        try:
            sha256 = hashlib.sha256()
            while True:
                block = f.read(CONFIG['buff_size'])
                if not block:
                    break
                sha256.update(block)
        finally:
            f.close()

        data = {
            'file': os.path.realpath(file),
            'file_size': os.path.getsize(file),
            'createdate': os.path.getctime(file),
            'modifydate': os.path.getmtime(file),
            'hash': sha256.hexdigest(),
            'status': 1,
            'severity': 0
        }

        if(compare_db(data, baseline)):
            baseline(**data).save()
            analytics.objects().update_one(inc__baseline=1)
            files.append(data)

    backup_baseline()
    SETTINGS["wait"] = False
    return jsonify({"ack": "Baseline successfully added"})    

def backup_baseline():
    count = 0
    for obj in baseline.objects():
        count = count + 1
        data_alt ={'file_id': str(obj.id)}
        data_alt['file'] = obj['file']
        data_alt['file_size'] = obj['file_size']
        data_alt['hash'] = obj['hash']
        data_alt['panel_id'] = count
        data_alt['status'] = 2
        data_alt['createdate'] = obj['createdate']
        data_alt['modifydate'] = obj['modifydate']
        data_alt['severity'] = 0
        
        if compare_db_gin(data_alt, baseline_bak):
            baseline_bak(**data_alt).save()
    return None

@app.route('/api2/baseline', methods=['GET'])
@token_required
def get_baseline():
    files = []

    for doc in baseline.objects():
        item = {'_id': str(doc.id)}
        item['file'] = doc['file']
        item['file_size'] = doc['file_size']
        item['createdate'] = doc['createdate']
        item['modifydate'] = doc['modifydate']
        item['hash'] = doc['hash']
        item['status'] = doc['status']

        files.append(item)

    return jsonify(files)

@app.route('/api2/baseline_bak', methods=['GET'])
@token_required
def get_baseline_bak():
    files = []
    for doc in baseline_bak.objects():
        item={}
        item['file_id'] = doc['file_id']
        item['file'] = doc['file']
        item['panel_id'] = doc['panel_id']
        item['file_size'] = doc['file_size']
        item['hash'] = doc['hash']
        item['status'] = doc['status']
        item['createdate'] = datetime.fromtimestamp(doc['createdate']).strftime('%d-%b-%Y %H:%M:%S')
        item['modifydate'] = datetime.fromtimestamp(doc['modifydate']).strftime('%d-%b-%Y %H:%M:%S')
        
        files.append(item)
    
    return jsonify(files)      

@app.route('/api2/verify', methods=['POST'])
@is_working
@token_required
def post_verify():
    if not baseline.objects():
        return jsonify({"error": "No baseline found"}), 400

    req = request.get_json()
    files = []
    SETTINGS['alert'] = req['alert']
    SETTINGS['manual'] = req['manual']
    SETTINGS['cron'] = req['cron']
    SETTINGS['interval'] = int(req['interval'])
    SETTINGS['auto_enc'] = req['auto_enc']

    if SETTINGS['manual'] == "True" or SETTINGS['manual']:
        files = verify()
    
    if SETTINGS['cron'] == "True" or SETTINGS['cron']:
        start_cron()
    else:
        stop_cron()

    return jsonify({"ack": "Configuration complete"}) 

def start_cron():
    if (cron.get_job('verify')):
        cron.reschedule_job('verify', trigger='interval', seconds=SETTINGS['interval'])
    else:
        cron.add_job(verify, 'interval', seconds=SETTINGS['interval'], id='verify')

def stop_cron():
    if(cron.get_job('verify')):
        cron.remove_job('verify')

def verify():
    if len(baseline.objects()) > 0:
        analytics.objects().update_one(inc__scans=1)
        scan_baseline(users, baseline, baseline_bak, alertlog, syslog, analytics, CONFIG['buff_size'], SETTINGS['alert'], SETTINGS['auto_enc'], keys)
        make_chart()
    else:
        return 0

def make_chart():
    item = {}
    item['baseline'] = [doc['baseline'] for doc in analytics.objects()][0]
    item['scans'] = [doc['scans'] for doc in analytics.objects()][0]
    item['alerts'] = [doc['alerts'] for doc in analytics.objects()][0]

    chart(**item).save()        

@app.route('/api2/analytics', methods=['GET'])
@token_required
def get_analytics():
    item = {}

    for doc in analytics.objects():
        item['baseline'] = doc['baseline']
        item['scans'] = doc['scans']
        item['alerts'] = doc['alerts']
        item['encs'] = doc['encs']
        item['risk'] = doc['risk']


    response = jsonify(item)
    return response

@app.route('/api2/syslog', methods=['GET'])
@token_required
def get_syslog():
    files = []
    
    for doc in syslog.objects():
        item = {'_id': str(doc.id)}
        item['scan_dnt'] = doc['scan_dnt']
        item['logs'] = doc['logs']

        files.append(item)

    response = jsonify(files)
    return response

@app.route('/api2/chart', methods=['GET'])
@token_required
def get_chart():
    files = []
    
    for doc in chart.objects():
        item = {}
        item['baseline'] = doc['baseline']
        item['scans'] = doc['scans']
        item['alerts'] = doc['alerts']

        files.append(item)
        
    return jsonify(files)

@app.route('/api2/removebaseline', methods=['POST'])
@is_working
@token_required
def post_removebaseline():
    req = request.get_json()

    if not req:
        return jsonify({"error": "Invalid file id"}), 400

    id = req['id']
    
    if not re.fullmatch(id_regex, id):
        return jsonify({"error": " file id must be a 12-byte input or a 24-character hex string"}), 400


    if not baseline.objects(id=id):
        return jsonify({"error": "Invalid file id"}), 400

    baseline.objects(id=id).delete()
    baseline_bak.objects(file_id=id).delete()
    analytics.objects().update_one(dec__baseline=1)   

    return jsonify({"ack": "Baseline removed successfully"})    

@app.route('/api2/removeall', methods=['POST'])
@is_working
@token_required
def post_removeall():
    try:
        base = baseline.objects
        if not base:
            raise Exception()
    except Exception:
        return jsonify({"error": "No baseline found"}), 400
    else:
        drop_collection([base, baseline_bak.objects, chart.objects])
        set_analyticsTozero(analytics.objects)
        return jsonify({"ack": "All baselines are removed successfully"}) 

@app.route('/api2/whoami', methods=['GET'])
@token_required
def get_whoami():
    user_data ={}
    for doc in users.objects(id=session['sess_id']):
        user_data['user'] = doc['user']
        user_data['email'] = doc['email']
        user_data['role'] = doc['role']

    return jsonify(user_data)

@app.route('/api2/encrypt', methods=['POST'])
@token_required
def post_pyzipp():
    req = request.get_json()

    if not baseline.objects():
        return jsonify({"error": "No baseline found"}), 400

    
    if baseline_bak.objects(file_id=req['id']).only('status').first().status == 4:
        return jsonify({"error": "File is moved or deleted"}), 400

    if not os.path.exists(baseline.objects(id=req['id']).only('file').first().file) and req['mode'] == 'Decrypt':
        return jsonify({"error": "Decryption failed, run a scan and try again"}), 400

    if not os.path.exists(baseline.objects(id=req['id']).only('file').first().file) and req['mode'] == 'Encrypt':
        return jsonify({"error": "Encryption failed, run a scan and try again"}), 400    

    try:
        response = zip(req['id'], req['mode'], baseline, baseline_bak, analytics, keys)
    except(PermissionError):
        baseline_bak.objects(file_id=req['id']).update_one(inc__status=5)
        analytics.objects().update_one(inc__encs=1)
        return ({"error": "File is already encrypted"}), 400
    else:
        return jsonify({"ack": response})

@app.route('/api2/updatepassword', methods=['POST'])
@token_required
def post_updatepassword():
    req = request.get_json()
    if not req:
        return jsonify({"error": "Icorrect password format"}), 400

    if not req['pass'] or not req['confirm_pass']:
        return jsonify({"error": "Icorrect password format"}), 400

    if not re.fullmatch(pw_regex, req['pass']):
        return jsonify({"error": "Icorrect password format"}), 400

    if not req['confirm_pass'] == req['pass']:    
        return jsonify({"error": "Passwords do not match"}), 400

    new_pw_hash = bcrypt.generate_password_hash(req['pass'])
    old_pw_hash = users.objects(id=session['sess_id']).only('password').first().password

    if bcrypt.check_password_hash(old_pw_hash, req['pass']):
        return jsonify({"error": "Password cannot be same as the old one"}), 400

    users.objects(id=session['sess_id']).update_one(set__password=new_pw_hash.decode())

    return jsonify({"ack": "Password successfully updated"})

@app.route('/api2/updateemail', methods=['POST'])
@token_required
def post_updateemail():
    req = request.get_json()
    
    if not req:
        return jsonify({"error": "Incorrect email format"}), 400

    if req['email'] == '':
        return jsonify({"error": "Incorrect email format"}), 400

    if not re.fullmatch(email_regex, req['email']):
        return jsonify({"error": "Incorrect email format"}), 400

    new_email = req['email']
    
    if users.objects(email=new_email):
        return jsonify({"error": "User alread exist with this email"}), 400

    old_email = users.objects(id=session['sess_id']).only('email').first().email
    if old_email == new_email:
        return jsonify({"error": "Email cannot be same as the old one"}), 400


    users.objects(id=session['sess_id']).update_one(set__email=new_email)
    
    return jsonify({"ack": "Email successfully updated"})

@app.route('/api2/quickscan', methods=['POST'])
@token_required
def post_quickscan():
    req = request.get_json()

    if not baseline.objects():
        return jsonify({"error": "No baseline found"}), 400

    if baseline_bak.objects(file_id=req['id']).only('status').first().status > 4:
        return jsonify({"error": "File is encrypted, can not perform quickscan"}), 400

    item = quick_scan(req['id'], baseline, baseline_bak, syslog, analytics, alertlog, BUFF_SIZE=CONFIG['buff_size'])
    analytics.objects().update_one(inc__scans=1)
    make_chart()

    if len(item) > 0:
        return jsonify({"ack": "Quickscan complete"})    


@app.route('/api2/setseverity', methods=['POST'])
@token_required
def post_setseverity():

    req = request.get_json()

    risk = int(req['risk'])
    analytics.objects().update_one(set__risk=risk)

    if risk == 0:
        baseline_bak.objects().update(set__severity=0)
    if risk == 1:
        baseline_bak.objects().update(set__severity=1)
        baseline_bak.objects(file__regex= '\.txt$').update(set__severity=0)
    if risk == 2:
        baseline_bak.objects().update(set__severity=1)

    return jsonify()

@app.route('/api2/cve/<cve>', methods=['GET'])
def get_cve(cve):
        data = get(f'https://cve.circl.lu/api/cve/{cve}').content.decode()
        content = json.loads(data)
        content_json = {'id': content['id'], 'name': content['capec'][0]['name'], 'summary': content['capec'][0]['summary'], 'solutions': content['capec'][0]['solutions']}
        return jsonify(content_json)

if __name__ == '__main__':
    app.run(host=CONFIG['host'], port=CONFIG['port'], debug=True, use_reloader=True)


