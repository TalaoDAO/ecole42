""" prevoir un install avec git clone puis un setp install sous venv """

import os
from smsapi.client import SmsApiComClient
from smsapi.exception import SmsApiException

token = 'Is4VwzWwpkxAnFdOWbVDZqc2IpcjukhGt5TXCkoG'
client = SmsApiComClient(access_token=token)


def send_code(phone, code) :
	""" code = str, phone number with country code 33607182594 """
	send_results = client.sms.send(to=phone, message="# Your verification code is : "+ code)
	for result in send_results:
		print(result.id, result.points, result.error)
	return
   

def check_phone(phone) :
	try:
		client.sms.send(to=phone, message="Your phone number has been checked.")
		return True
	except SmsApiException as e:
		print(e.message, e.code)
		return False

#send_code('33607182594', '123456')	
#print(check_phone('0607182594'))