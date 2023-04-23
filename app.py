import os
import pathlib
import requests
from flask import Flask, session, abort, redirect, request, jsonify, url_for
from flask_session import Session
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from google.cloud import firestore
from flask_bcrypt import Bcrypt
import tensorflow as tf
import tensorflow_hub as hub
import numpy as np
import pandas as pd
from pytz import timezone 
from datetime import datetime, timedelta
import string
import random
from flask_cors import CORS
import json
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__) 
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=5)
app.config["SESSION_COOKIE_SAMESITE"] = "None"
app.config["SESSION_COOKIE_SECURE"] = True
Session(app)
CORS(app, supports_credentials=True)
bcrypt = Bcrypt(app) 
app.secret_key = os.environ.get("SECRET_KEY")
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" 

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client-secret.json")  
db = firestore.Client(project='vskillup')

words = pd.read_csv("model/words.csv")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],  
    redirect_uri="http://127.0.0.1:5000/callback" 
)

def login_is_required(function):  
    def wrapper(*form, **kwform):
        if "google_id" not in session:  
            return abort(401)
        else:
            return function()

    return wrapper

def universal_login_condition():
    try:
        if 'google_id' in session:
            return redirect('/login_via_google')
        elif 'non_google_id' in session:
            return redirect('/welcome')
    except:
        return False

    return True

@app.route("/login_via_google")  
def login_via_google():
    try:
        if session['non_google_id']:
            return redirect('/welcome')
        
        if session['google_id']:
            return redirect('/protected_area')
    except:
        pass
    authorization_url, state = flow.authorization_url()  
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")  
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500) 

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["given_name"] = id_info.get("given_name")
    session["family_name"] = id_info.get("family_name")
    session['email'] = id_info.get("email")
    return redirect("/protected_area")  


@app.route("/logout")  
def logout():
    session.clear()
    return redirect("/")


@app.route("/")  
def index():
    context = {
        "login_via_google": "http://127.0.0.1:5000/login_via_google",
        "login via POST": "http://127.0.0.1:5000/login" 
    }
    return jsonify(context)


@app.route("/protected_area")  
@login_is_required
def protected_area():
    doc_ref = db.collection(u'users').document(session['email']).get().to_dict()
    if doc_ref is None:
        writeRegister(session['given_name'], session['family_name'], session['email'], bcrypt.generate_password_hash("auth-via-google"))

    return redirect('/welcome')

def writeRegister(fname, lname, email, pwd):
    try: 
        doc_ref = db.collection(u'users').document(email)
        doc_ref.set({
            u'first_name': fname,
            u'last_name': lname,
            u'email': email,
            u'password': pwd
        })
        return True
    except:
        return False    

@app.route("/register", methods=["POST", "GET"])
def register():
    try:
        if session['google_id']:
            return redirect('/login_via_google')
        elif session['non_google_id']:
            return redirect('/welcome')
    except:
        pass
    
    if request.method == "POST":
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        email = request.form.get('email')
        pwd = request.form.get('password')
        print(first_name, last_name, email, pwd)
        hash_pwd = bcrypt.generate_password_hash(pwd)

        users_ref = db.collection(u'users')
        
        try:
            if users_ref.document(email).get():
                data = users_ref.document(email).get().to_dict()
                if data:
                    context = {"registered": False, "main_page": "http://127.0.0.1:5000/"}
                    return jsonify(context)
        except:
            pass
        
        if writeRegister(first_name, last_name, email, hash_pwd):
            context = {"registered": True, "main_page": "http://127.0.0.1:5000/"}
            return jsonify(context)
        else:
            context = {"registered": False, "main_page": "http://127.0.0.1:5000/"}
            return jsonify(context)
    else:
        context = {
            "message": "Use POST request to register yourself!", 
            "main_page": "http://127.0.0.1:5000/"
        }
        return jsonify(context)

@app.route("/login", methods=["POST", "GET"])
def login():
    try:
        if 'google_id' in session:
            return redirect('/login_via_google')
        elif 'non_google_id' in session:
            return redirect('/welcome')
    except:
        pass
    
    if request.method == "POST":
        email = request.form.get('email')
        pwd = request.form.get('password')
        
        users_ref = db.collection(u'users')
        
        if users_ref.document(email).get():
            data = users_ref.document(email).get().to_dict()
            if not data:
                context = {
                        "success": False,
                        "message": "User email address not registered!",
                        "main_page": "http://127.0.0.1:5000/"
                    }
                return jsonify(context)
            if bcrypt.check_password_hash(data['password'], pwd):
                session['given_name'] = data['first_name']
                session['family_name'] = data['last_name']
                session['email'] = data['email']
                session['non_google_id'] = True
                return redirect(url_for('welcome', data = {
                    "given_name": f"{data['first_name']}",
                    "family_name": f"{data['last_name']}",
                    "email": f"{data['email']}"
                }))
            else:
                context = {
                    "success": False,
                    "message": "User password is invalid!",
                    "main_page": "http://127.0.0.1:5000/"
                }
                return jsonify(context)
        else:
            context = {
                    "success": False,
                    "message": "User email address not registered!",
                    "main_page": "http://127.0.0.1:5000/"
                }
            return jsonify(context)

    else:
        context = {
            "message": "Use POST request to login yourself!", 
            "main_page": "http://127.0.0.1:5000/"
        }
        return jsonify(context)

@app.route('/welcome', methods=["GET", "POST"])
def welcome():
    if universal_login_condition():
        if 'google_id' not in session:
            sessionData = json.loads(request.args['data'].replace("'", '"'))
            session['email'] = sessionData['email']
            session['given_name'] = sessionData['given_name']
            session['family_name'] = sessionData['family_name']
        data = db.collection(u'users').document(session['email']).get().to_dict()
        if not data:
            return redirect('/logout')
        
        if 'age' not in data.keys() or 'education' not in data.keys():
            return redirect(url_for('personalInformation', data = {
                "given_name": session['given_name'],
                "family_name": session['family_name'],
                "email": session['email'],
            }))
        
        session['age'] = data['age']
        session['education'] = data['education']
        
        if 'level' not in data.keys():
            return redirect(url_for('level', data={
                "given_name": session['given_name'],
                "family_name": session['family_name'],
                "email": session['email'],
                "age": session['age'],
                "education": session['education']
            }))
        
        session['level'] = data['level']

        context = {
            "success": True,
            "first_name": session['given_name'],
            "last_name": session['family_name'],
            "email": session['email'],
            "age": session['age'],
            "education": session['education'],
            "level": session['level'],
            "logout": "http://127.0.0.1:5000/logout" 
        }
        return jsonify(context)
    else:
        return redirect('/') 

def writePersonalInformation(age, education):
    try: 
        doc_ref = db.collection(u'users').document(session['email'])
        doc_ref.set({
            u'age': age,
            u'education': education
        }, merge=True)
        return True
    except:
        return False    

@app.route("/personalInformation", methods=['GET', 'POST'])
def personalInformation():
    if universal_login_condition():

        if request.method == "POST":
            age = request.form.get('age')
            education = request.form.get('education')
            if not session.get('given_name'):
                session['given_name'] = request.form.get('given_name')
            if not session.get('family_name'):
                session['family_name'] = request.form.get('family_name')
            if not session.get('email'):
                session['email'] = request.form.get('email')

            if not age or not education:
                context = {
                    "message": "Please add personal information via POST to proceed!",
                    "personalInformation": True,
                    "logout": "http://127.0.0.1:5000/logout" ,
                    "main_page": "http://127.0.0.1:5000",
                    "given_name": session['given_name'],
                    "family_name": session['family_name'],
                    "email": session['email']
                }
                return jsonify(context)

            if writePersonalInformation(age, education):
                print('called')
                return redirect(url_for('welcome', data = {
                    "given_name": session['given_name'],
                    "family_name": session['family_name'],
                    "email": session['email']
                }))
            
            else:
                print('Failed')
                context = {
                    "error": "Personal information could not be added! Please logout and retry!",
                    "logout": "http://127.0.0.1:5000/logout" ,
                    "main_page": "http://127.0.0.1:5000" 
                }
                return jsonify(context)
        else:
            sessionData = json.loads(request.args['data'].replace("'", '"'))
            session['email'] = sessionData['email']
            session['given_name'] = sessionData['given_name']
            session['family_name'] = sessionData['family_name']
            context = {
                "message": "Please add personal information via POST to proceed!",
                "personalInformation": True,
                "logout": "http://127.0.0.1:5000/logout" ,
                "main_page": "http://127.0.0.1:5000",
                "given_name": session['given_name'],
                "family_name": session['family_name'],
                "email": session['email']
            }
            return jsonify(context)
        
    else:
        return redirect('/')

def suggest_level(age, education):
    ageRange = ['Below 18', 'Between 18 to 40', 'Above 40']
    educationRange = ['Kindergarten', 'Primary School', 'Secondary School', 'Graduate', 'Post Graduate']
    
    combinations = {
        "Beginner": [(ageRange[0], educationRange[0]), (ageRange[0], educationRange[1]), (ageRange[1], educationRange[0]), (ageRange[2], educationRange[0])],
        "Intermediate": [(ageRange[0], educationRange[2]), (ageRange[0], educationRange[3]), (ageRange[1], educationRange[1]), (ageRange[1], educationRange[2]), (ageRange[2], educationRange[1]), (ageRange[2], educationRange[2])],
        "Advance": [(ageRange[1], educationRange[3]), (ageRange[1], educationRange[4]), (ageRange[0], educationRange[4]), (ageRange[2], educationRange[3]), (ageRange[2], educationRange[4])]
    }

    if not age:
        session['age'] = age
        
    if int(session['age']) < 18:
        age = ageRange[0]
    elif int(session['age']) >= 18 and int(session['age']) <40:
        age = ageRange[1]
    else:
        age = ageRange[2]

    if not education:
        education = session['education']
    
    pair = (age, education)
    for key, value in combinations.items():
        if pair in value:
            return key
    
    return 'Beginner'

@app.route('/level', methods=["GET", "POST"])
def level():
    if universal_login_condition():
        if request.method == "POST":
            level = request.form.get('level')
            if not session.get('given_name'):
                session['given_name'] = request.form.get('given_name')
            if not session.get('family_name'):
                session['family_name'] = request.form.get('family_name')
            if not session.get('email'):
                session['email'] = request.form.get('email')
                
            level.capitalize()
            if not level:
                context = {
                    "message": "Please add level via POST to proceed!",
                    "logout": "http://127.0.0.1:5000/logout" ,
                    "main_page": "http://127.0.0.1:5000" 
                }
                return jsonify(context)

            try:
                doc_ref = db.collection(u'users').document(session['email'])
                doc_ref.set({
                    u'level': level,
                }, merge=True)

                return redirect(url_for('welcome', data={
                    "given_name": session['given_name'],
                    "family_name": session['family_name'],
                    "email": session['email']
                }))
            except:
                context={
                    "error": "Could not write level!"
                }
                return jsonify(context)
        else:
            if 'level' in session:
                your_level = session['level']
                suggested_level = suggest_level(session['age'], session['education'])
                context = {
                        "your-level": your_level,
                        "suggested-level": suggested_level,
                        "apply-suggested-level": f"http://127.0.0.1:5000/level?level={suggested_level}"
                    }
                return jsonify(context)
            else:
                sessionData = json.loads(request.args['data'].replace("'", '"'))
                session['email'] = sessionData['email']
                session['given_name'] = sessionData['given_name']
                session['family_name'] = sessionData['family_name']
                session['age'] = sessionData['age']
                session['education'] = sessionData['education']
                context = {
                    "message": "You need to set your level via POST request",
                    "level": True,
                    "logout": "http://127.0.0.1:5000/logout",
                    "main_page": "http://127.0.0.1:5000",
                    "given_name": session['given_name'],
                    "family_name": session['family_name'],
                    "email": session['email'],
                    "age": session['age'],
                    "education": session['education']
                }
                return jsonify(context)
    else:
        try:
            sessionData = json.loads(request.args['data'].replace("'", '"'))
            session['email'] = sessionData['email']
            session['given_name'] = sessionData['given_name']
            session['family_name'] = sessionData['family_name']
            session['age'] = sessionData['age']
            session['education'] = sessionData['education']
            context = {
                    "message": "You need to set your level via POST request",
                    "level": True,
                    "logout": "http://127.0.0.1:5000/logout",
                    "main_page": "http://127.0.0.1:5000",
                    "given_name": session['given_name'],
                    "family_name": session['family_name'],
                    "email": session['email'],
                    "age": session['age'],
                    "education": session['education']
            }
            return jsonify(context)
        except:
            return redirect('/')

@app.route('/deleteAccount/<email>', methods=["GET", "POST"])
def deleteAccount(email):
    if universal_login_condition():
        if 'email' in session:
            if session['email'] == email:
                if request.method == "POST":
                    pwd = request.form.get('password')
                    data = db.collection(u'users').document(email).get().to_dict()
                    if not data:
                        context = {"error": "User does not exist!"}
                        return jsonify(context)
                    
                    if bcrypt.check_password_hash(data['password'], pwd):
                        try:
                            db.collections(u'users').document(email).delete()
                            return redirect('/logout')
                        except:
                            context = {"error": "Database service is down at the moment!"}
                            return jsonify(context)
                    else:
                        context = {"error": "Wrong password input!"}
                        return jsonify(context)
                else:
                    context = {
                        "message": "To delete your account, send a POST request with your password!",
                        "logout": "http://127.0.0.1:5000/logout",
                        "main_page": "http://127.0.0.1:5000" 
                    }
                    return jsonify(context)

            else:
                context = {
                    "error": "User email address does not match!"
                }
        else:
            redirect('/logout')
    else:
        return redirect('/')

def sentence_matching(query):
    tf.compat.v1.disable_eager_execution()
    def embed_useT(module):
        with tf.Graph().as_default():
            sentences = tf.compat.v1.placeholder(tf.string)
            embed = hub.Module(module)
            embeddings = embed(sentences)
            session = tf.compat.v1.train.MonitoredSession()
        return lambda x: session.run(embeddings, {sentences: x})
    embed_fn = embed_useT('model')
    encoding_matrix = embed_fn(query)
    return np.inner(encoding_matrix, encoding_matrix)

def sentence_matching_result(word, input):
    api = f"https://api.dictionaryapi.dev/api/v2/entries/en/{word}"
    r = requests.get(url=api)
    meaningDict = r.json()
    meaning = [input]
    for objects in meaningDict[0]['meanings'][0]['definitions']:
        meaning.append(objects['definition'])

    corr_mat = sentence_matching(meaning)
    result = corr_mat[0][:]
    return result, meaning

@app.route('/dailyChallenge', methods=["GET", "POST"])
def dailyChallenge():
    if universal_login_condition():
        india = datetime.now(timezone("Asia/Kolkata")).strftime('%Y-%m-%d')
        userData = db.collection(u'dailyChallenge').document(session['email']).get().to_dict()
        doc_ref = db.collection(u'dailyChallenge').document(session['email'])
        if userData is None:
            doc_ref.set({
                    'latest': (datetime.now(timezone("Asia/Kolkata"))-timedelta(1)).strftime('%Y-%m-%d'),
                    'streak': 0,
                })
        elif userData['latest']==india:
            context = {
                    'message': "You have solved today's daily challenge! Come back tomorrow for a new one!",
                    "logout": "http://127.0.0.1:5000/logout",
                    "main_page": "http://127.0.0.1:5000" 
                }
            return jsonify(context)

        if request.method == "POST":
            word = db.collection(u'dailyChallenge').document(u'challenge').get().to_dict()['word']
            if word is None:
                return redirect("/")
            input = request.form.get('sentence')
            result, meaning = sentence_matching_result(word, input)
            _index = np.argmax(result[1:], axis=0)
            userData = db.collection(u'dailyChallenge').document(session['email']).get().to_dict()
            doc_ref = db.collection(u'dailyChallenge').document(session['email'])   
            streak = False
            if result[1:][_index] > 0.5:
                streak = True
            doc_ref.set({
                'latest': india,
                'streak': userData['streak']+1 if streak else 0
            })         
            
            trackData = db.collection(u'trackDailyChallenge').document(session['email'])
            trackData.set({
                india: {
                    "word": word,
                    "meaning": meaning[1:][_index],
                    "accuracy": "{:.2f}".format(result[1:][_index]*100)
                }
            }, merge=True)
            
            context = {
                "word": word,
                "input": input,
                "meaning": meaning[1:][_index],
                "accuracy": "{:.2f}".format(result[1:][_index]*100),
                "streak" : "Maintained" if streak else "Broken"
            }
            
            return jsonify(context)
        else:
            india = datetime.now(timezone("Asia/Kolkata")).strftime('%Y-%m-%d')
            data = db.collection(u'dailyChallenge').document(u'challenge').get().to_dict()
            if data is None or data['date']!=india:
                word = generate_random_word()
                doc_ref = db.collection(u'dailyChallenge').document(u'challenge')
                doc_ref.set({
                    'date': india,
                    'word': word
                })
            else:
                word = data['word']
                    
            context = {
                "word": word,
                "logout": "http://127.0.0.1:5000/logout",
                "main_page": "http://127.0.0.1:5000" 
            }
            return jsonify(context)
    else:
        return redirect('/')

@app.route('/dailyChallengeForWebsite', methods=["POST"])
def dailyChallengeForWebsite():
    if request.form.get('email'):
        india = datetime.now(timezone("Asia/Kolkata")).strftime('%Y-%m-%d')
        userData = db.collection(u'dailyChallenge').document(request.form.get('email')).get().to_dict()
        doc_ref = db.collection(u'dailyChallenge').document(request.form.get('email'))
        if userData is None:
            doc_ref.set({
                    'latest': (datetime.now(timezone("Asia/Kolkata"))-timedelta(1)).strftime('%Y-%m-%d'),
                    'streak': 0,
                })
        elif userData['latest']==india:
            context = {
                    'message': "You have solved today's daily challenge! Come back tomorrow for a new one!",
                }
            return jsonify(context)

        if request.form.get('submit') == 'true':
            word = db.collection(u'dailyChallenge').document(u'challenge').get().to_dict()['word']
            if word is None:
                return redirect("/")
            input = request.form.get('sentence')
            result, meaning = sentence_matching_result(word, input)
            _index = np.argmax(result[1:], axis=0)
            userData = db.collection(u'dailyChallenge').document(request.form.get('email')).get().to_dict()
            doc_ref = db.collection(u'dailyChallenge').document(request.form.get('email'))   
            streak = False
            if result[1:][_index] > 0.5:
                streak = True
            doc_ref.set({
                'latest': india,
                'streak': userData['streak']+1 if streak else 0
            })         
            
            trackData = db.collection(u'trackDailyChallenge').document(request.form.get('email'))
            trackData.set({
                india: {
                    "word": word,
                    "meaning": meaning[1:][_index],
                    "accuracy": "{:.2f}".format(result[1:][_index]*100)
                }
            }, merge=True)
            
            context = {
                "word": word,
                "input": input,
                "meaning": meaning[1:][_index],
                "accuracy": "{:.2f}".format(result[1:][_index]*100),
                "streak" : "Maintained" if streak else "Broken"
            }
            
            return jsonify(context)
        else:
            india = datetime.now(timezone("Asia/Kolkata")).strftime('%Y-%m-%d')
            data = db.collection(u'dailyChallenge').document(u'challenge').get().to_dict()
            if data is None or data['date']!=india:
                word = generate_random_word()
                doc_ref = db.collection(u'dailyChallenge').document(u'challenge')
                doc_ref.set({
                    'date': india,
                    'word': word
                })
            else:
                word = data['word']
                    
            context = {
                "word": word,
            }
            return jsonify(context)
    else:
        return redirect('/')

def generate_random_word(level=None):
    while True:
        word = words.sample()
        word = str(word).split(' ')[-1]
        if level:
            if level == 'Beginner':
                if len(word)>5:
                    continue
            elif level == 'Intermediate':
                if len(word)<5 or len(word)>7:
                    continue
            else:
                if len(word) < 7:
                    continue
        api = f"https://api.dictionaryapi.dev/api/v2/entries/en/{word}"
        r = requests.get(url=api)
        meaningDict = r.json()
        try:
            if meaningDict['title'] == 'No Definitions Found':
                continue
            else:
                break
        except:
            break
    return word


@app.route('/learn', methods=["GET", "POST"])
def learn():
    if universal_login_condition():
        india = datetime.now(timezone("Asia/Kolkata")).strftime('%Y-%m-%d')
        data = db.collection(u'learn').document(session['email']).get().to_dict()
        if data is None or data['date']!=india:
            doc_ref = db.collection(u'learn').document(session['email'])
            doc_ref.set({
                'date': india,
                'count': 0
            })
        elif data['count'] >=10:
            context = {
                "message": "Daily limit reached! Return next day!",
                "logout": "http://127.0.0.1:5000/logout",
                "main_page": "http://127.0.0.1:5000" 
            }
            return jsonify(context)
        
        if request.method == "POST":
            word = request.form.get('word')
            input = request.form.get('sentence')
            if word.lower() == input.lower():
                context = {
                    "error": "Meaning cannot be same as the word!",
                    "logout": "http://127.0.0.1:5000/logout",
                    "main_page": "http://127.0.0.1:5000" 
                }
                return jsonify(context)
            result, meaning = sentence_matching_result(word, input)
            _index = np.argmax(result[1:], axis=0)
            context = {
                "input": input,
                "meaning": meaning[1:][_index],
                "accuracy": "{:.2f}".format(result[1:][_index]*100)
            }
            data = db.collection(u'learn').document(session['email']).get().to_dict()
            doc_ref = db.collection(u'learn').document(session['email'])
            doc_ref.set({
                'count': data['count']+1
            }, merge=True)
            return jsonify(context)
        else:
            word = generate_random_word(level=session['level'])            
            context = {
                "word": word,
                "logout": "http://127.0.0.1:5000/logout",
                "main_page": "http://127.0.0.1:5000" 
            }
            return jsonify(context)
    else:
        context = {
            "message": "Welcome to learn section. Here, we introduce you to our style of teaching!",
            "main_page": "http://127.0.0.1:5000" 
        }
        return jsonify(context)
    
@app.route('/learnOnWebsite', methods=["POST"])
def learnOnWebsite():
    if request.form.get('email'):
        session['email'] = request.form.get('email')
        session['level'] = request.form.get('level')
        india = datetime.now(timezone("Asia/Kolkata")).strftime('%Y-%m-%d')
        data = db.collection(u'learn').document(session['email']).get().to_dict()
        if data is None or data['date']!=india:
            doc_ref = db.collection(u'learn').document(session['email'])
            doc_ref.set({
                'date': india,
                'count': 0
            })
        elif data['count'] >=10:
            context = {
                "message": "Daily limit reached! Return next day!"
            }
            return jsonify(context)
        
        if request.form.get('submit') == "true":
            word = request.form.get('word')
            input = request.form.get('sentence')
            if word.lower() == input.lower():
                context = {
                    "error": "Meaning cannot be same as the word!"
                }
                return jsonify(context)
            result, meaning = sentence_matching_result(word, input)
            _index = np.argmax(result[1:], axis=0)
            context = {
                "input": input,
                "meaning": meaning[1:][_index],
                "accuracy": "{:.2f}".format(result[1:][_index]*100),
                "count": data['count']+1
            }
            data = db.collection(u'learn').document(session['email']).get().to_dict()
            doc_ref = db.collection(u'learn').document(session['email'])
            doc_ref.set({
                'count': data['count']+1
            }, merge=True)
            return jsonify(context)
        else:
            word = generate_random_word(level=session['level'])            
            context = {
                "word": word
            }
            return jsonify(context)
    else:
        context = {
            "message": "Welcome to learn section. Here, we introduce you to our style of teaching!"
        }
        return jsonify(context)

@app.route('/history')
def history():
    if universal_login_condition():
        trackData = db.collection(u'trackDailyChallenge').document(session['email']).get().to_dict()
        streak = db.collection(u'dailyChallenge').document(session['email']).get().to_dict()['streak']
        if trackData is None:
            context = {
                "message": "No history found! Create history by solving one ;)",
                "logout": "http://127.0.0.1:5000/logout",
                "main_page": "http://127.0.0.1:5000" 
            }
            return jsonify(context)
        context = {}
        for date, data in trackData.items():
            context[date] = f"Word: {data['word']} | Meaning: {data['meaning']} | Accuracy: {data['accuracy']}"
        
        context['streak'] = streak
        context['logout'] = "http://127.0.0.1:5000/logout"
        context['main_page'] = "http://127.0.0.1:5000"
        return jsonify(context)    
    else:
        redirect('/logout')    

@app.route("/createRoom")
def oneOnOneChallenge():
    if universal_login_condition():
        ROOM_ID_LENGTH = 10
        ROOM_ID = ''.join(random.choices(string.ascii_uppercase + string.digits, k=ROOM_ID_LENGTH))
        PASSWORD = ''.join(random.choices(string.ascii_uppercase + string.digits, k=ROOM_ID_LENGTH))
        context = {
            "room_id": ROOM_ID,
            "password": PASSWORD,
            "message": "This room will expire at 0000 hours!",
            "logout": "http://127.0.0.1:5000/logout",
            "main_page": "http://127.0.0.1:5000" 
        }
        room = db.collection(u'rooms').document(ROOM_ID).get().to_dict()
        india = datetime.now(timezone("Asia/Kolkata")).strftime('%Y-%m-%d')
        doc_ref = db.collection(u'rooms').document(ROOM_ID)
        if room is None or room['date']!=india:
            doc_ref.set({
                'date': india,
                'owner': session['email'],
                'ROOM_ID': ROOM_ID,
                'PASSWORD': PASSWORD 
            })
        else:
            return redirect('/createRoom')
        return jsonify(context)
    else:
        return redirect('/logout')

@app.route('/clearRoomCache')
def clearRoomCache():
    rooms = db.collection(u'rooms').stream()
    if rooms is None:
        return True
    india = datetime.now(timezone("Asia/Kolkata")).strftime('%Y-%m-%d')
    for id, data in rooms.items():
        if data['date']!=india:
            db.coolection(u'rooms').document(id).delete()
            
    return True    

if __name__ == "__main__": 
    app.run(debug=True)