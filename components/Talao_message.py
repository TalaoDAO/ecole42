import smtplib
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import codecs
import logging
logging.basicConfig(level=logging.INFO)
from flask_babel import  _

import constante

signature = '\r\n\r\n\r\n\r\nThe Ecole 42 team.\r\nhttps://42.fr/'

""" Envoi du code secret """
def messageAuth (email_to, random, mode) :

	password = mode.smtp_password

	# debut de la fonction
	fromaddr = "relay@talao.io"
	toaddr = [email_to, ]
#	toaddr = ['thierry.thevenet@talao.io' , 'thevenet_thierry@yahoo.fr']

	# instance of MIMEMultipart
	msg = MIMEMultipart()
	msg['From'] = formataddr((str(Header('Ecole 42', 'utf-8')), fromaddr))
	msg['To'] = ", ".join(toaddr)
	msg['Subject'] = 'Ecole 42 : Email authentification  '

	# string to store the body of the mail
	body = 'Your verification code is : '+ random
	msg.attach(MIMEText(body, 'plain'))
	#p = MIMEBase('application', 'octet-stream')

	# creates SMTP session
	s = smtplib.SMTP('smtp.gmail.com', 587)
	s.starttls()
	s.login(fromaddr, password)
	text = msg.as_string()

	# sending the mail
	try:
		s.sendmail(msg['from'],  msg["To"].split(","), text)
		s.quit()
		return True
	except:
		logging.error('sending mail')
		s.quit()
		return False
	

""" email envoyé a la creation d'un workspace  """
def messageLog(name, firstname, username, email,status,eth_a, eth_p, workspace_contract_address, backend_Id, login, SECRET, AES_key,mode)  :

	password = mode.smtp_password

	# debut de la fonction
	fromaddr = 'relay@talao.io'
	toaddr = [mode.admin, ]
#	toaddr = ['thierry.thevenet@talao.io' , 'thevenet_thierry@yahoo.fr']

	# instance of MIMEMultipart
	msg = MIMEMultipart()
	# storing the senders email address
	msg['From'] = formataddr((str(Header('Ecole 42', 'utf-8')), fromaddr))
	# storing the receivers email address
	msg['To'] = ", ".join(toaddr)
	# storing the subject
	msg['Subject'] = 'New account '
	# string to store the body of the mail
	body = "".join([_('A new account has been deployed\r\nUsername : '),
					username,
					'\r\n\r\nEmail : ',
					email,
					'\r\nChain : ',
					mode.BLOCKCHAIN,
					'\r\nAddress : ',
					str(eth_a),
					'\r\nWorkspace Address : ',
					str(workspace_contract_address),
					'\r\nStatus : ',
					status,
					])
	# attach the body with the msg instance
	msg.attach(MIMEText(body, 'plain'))
	"""
	# open the file to be sent
	path = "./RSA_key/"+mode.BLOCKCHAIN+'/'+eth_a+"_TalaoAsymetricEncryptionPrivateKeyAlgorithm1.txt"
	filename = eth_a+"_TalaoAsymetricEncryptionPrivateKeyAlgorithm1.txt"
	attachment = open(path, "rb")
	# instance of MIMEBase and named as p
	p = MIMEBase('application', 'octet-stream')
	# To change the payload into encoded form
	p.set_payload((attachment).read())
	# encode into base64
	encoders.encode_base64(p)
	p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
	# attach the instance 'p' to instance 'msg'
	msg.attach(p)
	"""
	# creates SMTP session
	s = smtplib.SMTP('smtp.gmail.com', 587)
	# start TLS for security
	s.starttls()
	# Authentication
	s.login(fromaddr, password)
	# Converts the Multipart msg into a string
	text = msg.as_string()
	# sending the mail
	try:
		s.sendmail(msg['from'],  msg["To"].split(","), text)
		logging.info('email sent')
	except:
		logging.info('sending mail')
	s.quit()
	return True

# dict of HTML templates with commented formating needed
HTML_templates = {'register' : 'templates/emails/register.html', # username
 				  'certificate_issued' : 'templates/emails/certificate_issued.html', # username
				   'certificate_issued_fr' : 'templates/emails/certificate_issued_fr.html', # username
				  'certificate_issued_issuer': 'templates/emails/certificate_issued_issuer.html', # username link
				  'request_partnership': 'templates/emails/request_partnership.html', # username link
				  'request_partnership_rejected': 'templates/emails/request_partnership_rejected.html', # name text
				  'forgot_password': 'templates/emails/forgot_password.html', # link
				  'added_referent': 'templates/emails/added_referent.html', # name
				  'POI_request_sent': 'templates/emails/request_POI_sent.html', # None
				  'POI_issued': 'templates/emails/POI_issued.html', # None
				  'invite_to_join': 'templates/emails/invite_to_join.html', # name
				  'job_offer': 'templates/emails/job_offer.html', # name, link, job
				  'memo' : 'templates/emails/memo.html', # name , memo
				  'code_auth' : 'templates/emails/code_auth.html', # code
				  	'code_auth_fr' : 'templates/emails/code_auth_fr.html', # code
				  'request_certificate' : 'templates/emails/request_certificate.html'} #name link

def messageHTML(subject, to, HTML_key, format_dict, mode)  :
	''' format_dict is a dictionnary with the necessary formating information
		ex: {'username' : 'Jack', 'text' : 'hello world'}
		The HTML file must be formated like a python str (ex for a name: {name})
		and the CSS part must use double {} ex: body {{
														margin: 0;
														padding: 0;
													 }}
		all images must be links to the Talao website
		ex: src="https://talao.co/static/img/logo.png	"'''
	password = mode.smtp_password
	fromaddr = "relay@talao.io"
	toaddr = [to]

	msg = MIMEMultipart()
	msg['From'] = formataddr((str(Header('Talao', 'utf-8')), fromaddr))
	msg['To'] = ", ".join(toaddr)
	msg['Subject'] = subject
	# string to store the body of the mail

	if HTML_key not in HTML_templates:
		logging.error('wrong HTML_key')
		return False


	template = HTML_templates[HTML_key]
	try :
		html = str(codecs.open(template, 'r', 'utf-8').read()).format(**format_dict)
	except Exception as e:
		logging.error('%s', str(e))
		return False

	msg.attach(MIMEText(html, 'html', 'utf-8'))
	#p = MIMEBase('application', 'octet-stream')

	# creates SMTP session
	s = smtplib.SMTP('smtp.gmail.com', 587)
	s.starttls()
	s.login(fromaddr, password)
	text = msg.as_string()

	# sending the mail
	try:
		s.sendmail(msg['from'],  msg["To"].split(","), text)
		logging.info('email sent')
		s.quit()
		return True
	except:
		logging.error('sending mail')
		s.quit()
		return False
	
def messageUser(name, firstname, username, email,eth_a, eth_p, workspace_contract_address,mode)  :

	password = mode.smtp_password
	fromaddr = "relay@talao.io"
	toaddr = [email]

	msg = MIMEMultipart()
	msg['From'] = formataddr((str(Header('Ecole 42', 'utf-8')), fromaddr))
	msg['To'] = ", ".join(toaddr)
	msg['Subject'] = 'Your certificates by Ecole 42'
	# string to store the body of the mail

	html = str(codecs.open("templates/emails/register.html", 'r', 'utf-8').read()).format(username = username)
	msg.attach(MIMEText(html, 'html', 'utf-8'))
	#p = MIMEBase('application', 'octet-stream')

	# creates SMTP session
	s = smtplib.SMTP('smtp.gmail.com', 587)
	s.starttls()
	s.login(fromaddr, password)
	text = msg.as_string()

	# sending the mail
	try:
		s.sendmail(msg['from'],  msg["To"].split(","), text)
		logging.info('email sent')
	except:
		logging.error('sending mail')
		return False
	s.quit()
	return True

def message(subject, to, messagetext, mode) :


	password = mode.smtp_password

	fromaddr = "relay@talao.io"
	toaddr = [to]

	msg = MIMEMultipart()
	msg['From'] = formataddr((str(Header('Talao', 'utf-8')), fromaddr))
	msg['To'] = ", ".join(toaddr)
	msg['Subject'] =  subject
	body = messagetext + signature
	msg.attach(MIMEText(body, 'plain'))
	#p = MIMEBase('application', 'octet-stream')

	# creates SMTP session
	s = smtplib.SMTP('smtp.gmail.com', 587)
	s.starttls()
	s.login(fromaddr, password)
	text = msg.as_string()

	# sending the mail
	try:
		s.sendmail(msg['from'],  msg["To"].split(","), text)
	except:
		logging.error('sending mail')
		return False
	s.quit()
	return True

def message_file(to, text, subject, filename, path, mode)  :
	""" 
	@to is list of email, 
	@filename is a list of files 
	"""

	password = mode.smtp_password

	# debut de la fonction
	fromaddr = "relay@talao.io"
	toaddr = to
#	toaddr = ['thierry.thevenet@talao.io' , 'thevenet_thierry@yahoo.fr']

	# instance of MIMEMultipart
	msg = MIMEMultipart()
	# storing the senders email address
	msg['From'] = formataddr((str(Header('Talao', 'utf-8')), fromaddr))
	# storing the receivers email address
	msg['To'] = ", ".join(toaddr)
	# storing the subject
	msg['Subject'] = subject
	# string to store the body of the mail
	body = text
	# attach the body with the msg instance
	msg.attach(MIMEText(body, 'plain'))

	for myfile in filename :
		# open the file to be sent
		file_with_path = path + myfile
		filename = myfile
		attachment = open(file_with_path, "rb")
		# instance of MIMEBase and named as p
		p = MIMEBase('application', 'octet-stream')
		# To change the payload into encoded form
		p.set_payload((attachment).read())
		# encode into base64
		encoders.encode_base64(p)
		p.add_header('Content-Disposition', "attachment; filename= %s" % filename)
		# attach the instance 'p' to instance 'msg'
		msg.attach(p)
	# creates SMTP session
	s = smtplib.SMTP('smtp.gmail.com', 587)
	# start TLS for security
	s.starttls()
	# Authentication
	s.login(fromaddr, password)
	# Converts the Multipart msg into a string
	text = msg.as_string()
	# sending the mail
	try:
		s.sendmail(msg['from'],  msg["To"].split(","), text)
		logging.info('email sent')
		s.quit()
		return True
	except:
		logging.error('sending mail')
		s.quit()
		return False
