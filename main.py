"""
TALAO CREDENTIAL REPOSITORY

if script is launched without Gunicorn, setup environment variables first :
$ export MYCHAIN=talaonet
$ export MYENV=livebox
 NO -> $ export AUTHLIB_INSECURE_TRANSPORT=1
$ python main.py

"""

import os
import time
import json
from flask_babel import Babel, _, refresh
from flask import Flask, redirect, jsonify, request, session
from flask_session import Session
from datetime import timedelta
from flask_cors import CORS
from flask_qrcode import QRcode
import redis

import logging
logging.basicConfig(level=logging.INFO)


# Environment variables set in gunicornconf.py  and transfered to environment.py
import environment
mychain = os.getenv('MYCHAIN')
myenv = os.getenv('MYENV')
if not myenv :
   myenv='liveboxw'
mychain = 'talaonet'

logging.info('start to init environment')
mode = environment.currentMode(mychain,myenv)
logging.info('end of init environment')

# Redis init red = redis.StrictRedis()
red= redis.Redis(host='localhost', port=6379, db=0)

# Centralized  routes : modules in ./routes
from routes import web_register, web_certificate, web_issuer, web_directory
from routes import web_data_user, web_skills, web_external, web_issuer_explore, web_revocationlist
from routes import web_main, web_login, repository, web_wallet_download,  web_tiar, web_app

#BUNNEY Calum <calum.bunney@nexusgroup.com>
# Server Release
VERSION = '0.2.0'
logging.info('Ecole42 version : %s', VERSION)

# Framework Flask and Session setup
app = Flask(__name__)
app.jinja_env.globals['Version'] = VERSION
app.jinja_env.globals['Created'] = time.ctime(os.path.getctime('main.py'))
app.jinja_env.globals['Chain'] = mychain.capitalize()
app.config['SESSION_PERMANENT'] = True
app.config['SESSION_COOKIE_NAME'] = 'talao'
app.config['SESSION_TYPE'] = 'redis' # Redis server side session
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=360) # cookie lifetime
app.config['SESSION_FILE_THRESHOLD'] = 100
app.config['SECRET_KEY'] = "OCML3BRawWEUeaxcuKHLpw" + mode.password
app.config["ALLOWED_IMAGE_EXTENSIONS"] = ["jpeg", "jpg", "png", "gif"]
babel = Babel(app)
sess = Session()
sess.init_app(app)
qrcode = QRcode(app)
CORS(app)

@app.errorhandler(403)
def page_abort(e):
    """
    we set the 403 status explicitly
    """
    logging.warning('abort 403')
    return redirect(mode.server + 'login/')


LANGUAGES = ['en', 'fr']
@babel.localeselector
def get_locale():
    if not session.get('language') :
        session['language'] = request.accept_languages.best_match(LANGUAGES)
    else :
        refresh()
    return session['language']


"""
https://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-xiii-i18n-and-l10n
pybabel extract -F babel.cfg -o messages.pot .
pybabel update -i messages.pot -d translations -l fr
pybabel compile -d translations

"""

@app.route('/language', methods=['GET'], defaults={'mode': mode})
def user_language(mode) :
    session['language'] = request.args['lang']
    refresh()
    return redirect (request.referrer)

logging.info('start init routes')
# Centralized @route
web_register.init_app(app, red, mode)
web_wallet_download.init_app(app, red, mode)
web_login.init_app(app, red,  mode)
web_certificate.init_app(app, mode)
web_external.init_app(app, mode)
web_directory.init_app(app, mode)
web_issuer_explore.init_app(app, mode)
web_data_user.init_app(app,red,mode)
web_issuer.init_app(app, mode)
web_revocationlist.init_app(app, red, mode)
web_tiar.init_app(app)
web_app.init_app(app, red, mode)
logging.info('end init routes')


# Centralized route issuer for skills
app.add_url_rule('/user/update_skills',  view_func=web_skills.update_skills, methods = ['GET', 'POST'], defaults={'mode': mode})


# Centralized route for main features
app.add_url_rule('/verifier/',  view_func=web_main.verifier, methods = ['GET', 'POST'])
app.add_url_rule('/getDID',  view_func=web_main.getDID, methods = ['GET'])
app.add_url_rule('/user/generate_identity/',  view_func=web_main.generate_identity, methods = ['GET', 'POST'],  defaults={'mode' : mode})
app.add_url_rule('/homepage/',  view_func=web_main.homepage, methods = ['GET'])
app.add_url_rule('/user/picture/',  view_func=web_main.picture, methods = ['GET', 'POST'], defaults={'mode' : mode})
app.add_url_rule('/user/success/',  view_func=web_main.success, methods = ['GET'], defaults={'mode' : mode})
app.add_url_rule('/user/update_search_setting/',  view_func=web_main.update_search_setting, methods = ['GET', 'POST'], defaults={'mode' : mode})
app.add_url_rule('/user/update_phone/',  view_func=web_main.update_phone, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/update_password/',  view_func=web_main.update_password, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/signature/',  view_func=web_main.signature, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/report',  view_func=web_main.report, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/tutotial/',  view_func=web_main.tutorial, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/prefetch',  view_func=web_main.prefetch, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/search/',  view_func=web_main.search, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/select_identity/',  view_func=web_main.select_identity, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/issue_certificate/',  view_func=web_main.issue_certificate, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/issue_studentcard/',  view_func=web_main.issue_studentcard, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/issue_completion/',  view_func=web_main.issue_completion, methods = ['GET','POST'], defaults={'mode' : mode})

app.add_url_rule('/company/add_credential_supported/',  view_func=web_main.add_credential_supported, methods = ['GET','POST'], defaults={'mode' : mode})

app.add_url_rule('/user/update_personal_settings/',  view_func=web_main.update_personal_settings, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/update_company_settings/',  view_func=web_main.update_company_settings, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/store_file/',  view_func=web_main.store_file, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/add_experience',  view_func=web_main.add_experience, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/add_activity',  view_func=web_main.add_activity, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/presentation/',  view_func=web_main.presentation, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/swap_privacy/',  view_func=web_main.swap_privacy, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/remove_certificate/',  view_func=web_main.remove_certificate, methods = ['GET','POST'], defaults={'mode' : mode})

app.add_url_rule('/user/remove_experience',  view_func=web_main.remove_experience, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/remove_education',  view_func=web_main.remove_education, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/create_company/',  view_func=web_main.create_company, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/create_promotion/',  view_func=web_main.create_promotion, methods = ['GET','POST'], defaults={'mode' : mode})

app.add_url_rule('/user/create_user/',  view_func=web_main.create_user, methods = ['GET','POST'], defaults={'mode' : mode})

app.add_url_rule('/user/remove_file/',  view_func=web_main.remove_file, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/add_education',  view_func=web_main.add_education, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/invit/',  view_func=web_main.invit, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/send_memo/',  view_func=web_main.send_memo, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/request_partnership/',  view_func=web_main.request_partnership, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/remove_partner/',  view_func=web_main.remove_partner, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/reject_partner/',  view_func=web_main.reject_partner, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/authorize_partner/',  view_func=web_main.authorize_partner, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/add_alias/',  view_func=web_main.add_alias, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/company/remove_access',  view_func=web_main.remove_access, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/import_private_key/',  view_func=web_main.import_private_key, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/import_rsa_key/',  view_func=web_main.import_rsa_key, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/request_proof_of_identity/',  view_func=web_main.request_proof_of_identity, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/add_issuer/',  view_func=web_main.add_issuer, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/add_key/',  view_func=web_main.add_key_for_other, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/delete_identity/',  view_func=web_main.delete_identity, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/uploads/<filename>',  view_func=web_main.send_file, defaults={'mode' : mode})
app.add_url_rule('/fonts/<filename>',  view_func=web_main.send_fonts)
app.add_url_rule('/help/',  view_func=web_main.send_help, methods = ['GET','POST'])
app.add_url_rule('/user/download/',  view_func=web_main.download_file, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/download_rsa_key/',  view_func=web_main.download_rsa_key, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/talao_ca/',  view_func=web_main.ca, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/download_x509/',  view_func=web_main.download_x509, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/download_pkcs12/',  view_func=web_main.download_pkcs12, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/download_QRCode/',  view_func=web_main.download_QRCode, methods = ['GET','POST'], defaults={'mode' : mode})
app.add_url_rule('/user/typehead/',  view_func=web_main.typehead, methods = ['GET','POST'])
app.add_url_rule('/user/data/',  view_func=web_main.talao_search, methods = ['GET','POST'], defaults={'mode' : mode})


# Centralized route for repository
app.add_url_rule('/repository/authn',  view_func=repository.authn, methods = ['POST'], defaults={'mode' : mode})
app.add_url_rule('/repository/publish',  view_func=repository.publish, methods = ['POST'], defaults={'mode' : mode})
app.add_url_rule('/repository/create',  view_func=repository.create, methods = ['GET'], defaults={'mode' : mode})
app.add_url_rule('/repository/get',  view_func=repository.get, methods = ['POST'], defaults={'mode' : mode})


# Google universal link
@app.route('/.well-known/assetlinks.json' , methods=['GET']) 
def assetlinks(): 
    document = json.load(open('assetlinks.json', 'r'))
    return jsonify(document)


# Apple universal link
@app.route('/.well-known/apple-app-site-association' , methods=['GET']) 
def apple_app_site_association(): 
    document = json.load(open('apple-app-site-association', 'r'))
    return jsonify(document)


# MAIN entry point for test
if __name__ == '__main__':
    # info release
    logging.info('flask test serveur run with debug mode')
    app.run(host = mode.flaskserver, port= mode.port, debug = mode.test, threaded=True)