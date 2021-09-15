from flask import jsonify, request, render_template, session, redirect, flash, Response
import json
from components import privatekey, Talao_message
import uuid
import secrets
from datetime import timedelta, datetime
import logging
logging.basicConfig(level=logging.INFO)
from signaturesuite import vc_signature
from flask_babel import _
import secrets

OFFER_DELAY = timedelta(seconds= 10*60)
DID_WEB = 'did:web:talao.cp'
DID_ETHR = 'did:ethr:0xee09654eedaa79429f8d216fa51a129db0f72250'
DID_TZ = 'did:tz:tz2NQkPq3FFA3zGAyG8kLcWatGbeXpHMu7yk'
DID = DID_ETHR


def init_app(app,red, mode) :
    app.add_url_rule('/emailpass',  view_func=emailpass, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/emailpass/qrcode',  view_func=emailpass_qrcode, methods = ['GET', 'POST'], defaults={'mode' : mode, 'red' : red})
    app.add_url_rule('/emailpass/offer/<id>',  view_func=emailpass_offer, methods = ['GET', 'POST'], defaults={'mode' : mode, 'red' : red})
    app.add_url_rule('/emailpass/authentication',  view_func=emailpass_authentication, methods = ['GET', 'POST'], defaults={'mode' : mode})
    app.add_url_rule('/emailpass/stream',  view_func=emailpass_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    app.add_url_rule('/emailpass/end',  view_func=emailpass_end, methods = ['GET', 'POST'])
    return

"""
Email Pass : credential offer for a VC with email only
VC is signed by Talao

"""

def emailpass(mode) :
    if request.method == 'GET' :
        return render_template('emailpass/emailpass.html')
    if request.method == 'POST' :
        # traiter email
        session['email'] = request.form['email']
        session['code'] = str(secrets.randbelow(99999))
        session['code_delay'] = datetime.now() + timedelta(seconds= 180)
        try : 
            subject = 'Talao : Email authentification  '
            Talao_message.messageHTML(subject, session['email'], 'code_auth', {'code' : session['code']}, mode)
            logging.info('secret code sent = %s', session['code'])
            flash(_(_("Secret code sent to your email.")), 'success')
            session['try_number'] = 1
        except :
            flash(_("Email failed."), 'danger')
            return render_template('emailpass/email.html.html')
    return redirect ('emailpass/authentication')


def emailpass_authentication(mode) :
    if request.method == 'GET' :
        return render_template('emailpass/emailpass_authentication.html')
    if request.method == 'POST' :
        code = request.form['code']
        session['try_number'] +=1
        logging.info('code received = %s', code)
        if code == session['code'] and datetime.now() < session['code_delay'] :
    	    # success exit
    	    return redirect(mode.server + 'emailpass/qrcode')
        elif session['code_delay'] < datetime.now() :
    	    flash(_("Code expired."), "warning")
    	    return render_template('emailpass/emailpass.html')
        elif session['try_number'] > 3 :
    	    flash(_("Too many trials (3 max)."), "warning")
    	    return render_template('emailpass/emailpass.html')
        else :
    	    if session['try_number'] == 2 :
    		    flash(_('This code is incorrect, 2 trials left.'), 'warning')
    	    if session['try_number'] == 3 :
    		    flash(_('This code is incorrect, 1 trial left.'), 'warning')
    	    return render_template("emailpass/emailpass_authentication.html")


def emailpass_qrcode(red, mode) :
    if request.method == 'GET' :
        id = str(uuid.uuid1())
        url = mode.server + "emailpass/offer/" + id 
        red.set(id,  session['email'])
        logging.info('url = %s', url)
        return render_template('emailpass/emailpass_qrcode.html', url=url, id=id)
   

def emailpass_offer(id, red, mode):
    """ Endpoint for wallet
    """
    credential = json.loads(open('./verifiable_credentials/EmailPass.jsonld', 'r').read())
    credential["issuer"] = DID
    credential['id'] = "urn:uuid:..."
    credential['credentialSubject']['id'] = "did:..."
    credential['issuanceDate'] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    credential['credentialSubject']['email'] = red.get(id).decode()
    #credential['proof'] =  {"@context": [],"type": "","proofPurpose": "","verificationMethod": "","created": "","jws": ""}
    credential['credentialSubject']['expires'] = (datetime.now() + timedelta(days= 365)).isoformat()[:10]  
    if request.method == 'GET': 
        # make an offer  
        credential_offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat()
        }
        return jsonify(credential_offer)
    elif request.method == 'POST': 
        red.delete(id)   
        # sign credential
        credential['id'] = "urn:uuid:" + str(uuid.uuid1())
        credential['credentialSubject']['id'] = request.form.get('subject_id', 'unknown DID')
        #del credential['proof']
        pvk = privatekey.get_key(mode.owner_talao, 'private_key', mode)
        signed_credential = vc_signature.sign(credential, pvk, DID)
        if not signed_credential :
            logging.error('credential signature failed')
            data = json.dumps({"url_id" : id, "check" : "failed"})
            red.publish('credible', data)
            return jsonify({})
         # store signed credential on server
        try :
            filename = credential['id'] + '.jsonld'
            path = "./signed_credentials/"
            with open(path + filename, 'w') as outfile :
                json.dump(json.loads(signed_credential), outfile, indent=4, ensure_ascii=False)
        except :
            logging.error('signed credential not stored')
        # send event to client agent to go forward
        data = json.dumps({"url_id" : id, "check" : "success"})
        red.publish('credible', data)
        print(signed_credential)
        return jsonify(signed_credential)
 

def emailpass_end() :
    if request.args['followup'] == "success" :
        message = _('Great ! you have now an Email Pass.')
    elif request.args['followup'] == 'expired' :
        message = _('Delay expired.')
    return render_template('emailpass/emailpass_end.html', message=message)


# server event push 
def event_stream(red):
    pubsub = red.pubsub()
    pubsub.subscribe('credible')
    for message in pubsub.listen():
        if message['type']=='message':
            yield 'data: %s\n\n' % message['data'].decode()


def emailpass_stream(red):
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
