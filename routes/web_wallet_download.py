from flask import jsonify, request, render_template, session, redirect, flash, Response
import json
from datetime import timedelta, datetime
from flask_babel import _
from urllib.parse import urlencode
from signaturesuite import vc_signature
from components import privatekey, ns

import logging
logging.basicConfig(level=logging.INFO)

""" download credential to wallet
those credential have been signed previously

"""
WORKSPACE_ECOLE42 = '0x1ad72C87B44422a98840df873Ad65822f71e7aDd'
OFFER_DELAY = timedelta(seconds= 10*60)
did_ecole42 = 'to be defined'

def init_app(app,red, mode) :
    app.add_url_rule('/wallet_download/credentialOffer/<id>',  view_func=credentialOffer_qrcode, methods = ['GET', 'POST'], defaults={'red' : red, 'mode' : mode})
    app.add_url_rule('/wallet_download/credential/<id>',  view_func=credential_display, methods = ['GET', 'POST'])
    app.add_url_rule('/wallet_download/wallet_credential/<id>',  view_func=credentialOffer, methods = ['GET', 'POST'], defaults={'red' : red, 'mode': mode})
    app.add_url_rule('/wallet_download/save_stream',  view_func=download_save_stream, methods = ['GET', 'POST'], defaults={'red' : red})
    global did_ecole42
    did_ecole42 =  ns.get_did(WORKSPACE_ECOLE42, mode)
    print("did ecole 42 = ", did_ecole42)
    return


def credentialOffer_qrcode(red, mode,id) :
    filename = id + ".jsonld"
    red.set(id, session['workspace_contract'])
    try :
        json.load(open('./signed_credentials/' + filename, 'r'))
    except :
        flash(_('This credential is not available.'), 'warning')
        return redirect("/user")
    url = mode.server + "wallet_download/wallet_credential/" + id + '?' + urlencode({'issuer' : did_ecole42})
    return render_template('download/credential_qr.html', url=url, id=id, **session['menu'])


def credential_display(id):
    if id != 'presentation' :
        filename = id + ".jsonld"
        credential = open('./signed_credentials/' + filename, 'r').read()
    else :
        credential = _('No credential available.')
    return render_template('download/credential.html', credential=credential)


def credentialOffer(id, red, mode):
    global did_ecole42
    filename = id + "_ecole42.jsonld"
    credential = json.loads(open('./to_be_signed_credentials/' + filename, 'r').read())
    credential['issuer'] = did_ecole42
    # Attention c est déja signé !!!!
    if request.method == 'GET':
        offer = {
            "type": "CredentialOffer",
            "credentialPreview": credential,
            "expires" : (datetime.now() + OFFER_DELAY).replace(microsecond=0).isoformat() + "Z", 
            "scope" : [],
            "display" : {"backgroundColor" : "ffffff"}
        }   
        if credential["credentialSubject"]["type"] == "ProfessionalStudentCard" :
            offer["shareLink"] = "https://42.fr/secret_code"
        return jsonify(offer), 200

    elif request.method == 'POST':
        workspace_contract = red.get(id).decode()
        user_did = request.form.get('subject_id')
        if user_did not in ns.get_did_list(workspace_contract,mode) :
            ns.add_did(workspace_contract, user_did, mode)
        # sign credential,
        credential['credentialSubject']['id'] = user_did
        credential["issuanceDate"] = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
        address_ecole42 = ns.get_data_from_username('ecole42', mode)['address']
        private_key_value = privatekey.get_key(address_ecole42, 'private_key', mode) 
        try :
            signed_credential = vc_signature.sign(credential, private_key_value, credential['issuer'])
            logging.info('credential signed')
        except :
            logging.error('signing failes')
            data = json.dumps({'id' : id, 'check' : 'server_error'})
            red.publish('wallet_download', data)
            return jsonify('Signing error'), 500
        data = json.dumps({'id' : id, 'check' : 'success'})
        red.publish('credible', data)
        return jsonify(signed_credential)
     

# server event push 
def event_stream(red):
    pubsub = red.pubsub()
    pubsub.subscribe('wallet_download')
    for message in pubsub.listen():
        if message['type']=='message':
            yield 'data: %s\n\n' % message['data'].decode()


def download_save_stream(red):
    headers = { "Content-Type" : "text/event-stream",
                "Cache-Control" : "no-cache",
                "X-Accel-Buffering" : "no"}
    return Response(event_stream(red), headers=headers)
