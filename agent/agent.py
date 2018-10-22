#coding:utf-8

import imaplib
import email
import base64
import json
import time

imaplib.Debug = 4
	

class Agent:
	def __init__(self,user,password,host="localhost"):
		self.server_config = {"host":"","user":"","password":""}
		self.transfer_messageid_lst = []
		
		self.server_config["host"] = host
		self.server_config["user"] = user
		self.server_config["password"] = password

		self.connection = imaplib.IMAP4_SSL(self.server_config["host"])
		self.connection.login(self.server_config["user"],self.server_config["password"])
		self.connection.select("INBOX",readonly=False)

		self.idle_command = "{0} IDLE\r\n".format(self.connection._new_tag().decode("UTF-8"))
		self.connection.send(self.idle_command.encode())


	def	fetch(self,num):
		tmp_connection = imaplib.IMAP4_SSL(self.server_config["host"])
		tmp_connection.login(self.server_config["user"],self.server_config["password"])
		tmp_connection.select("INBOX",readonly=True)
		typ,data = tmp_connection.fetch(num,"(RFC822)")
		tmp_connection.close()
		tmp_connection.logout()
		return typ,data


	def append(self,message):
		tmp_connection = imaplib.IMAP4_SSL(self.server_config["host"])
		tmp_connection.login(self.server_config["user"],self.server_config["password"])
		tmp_connection.select("INBOX",readonly=False)
		tmp_connection.append("INBOX","",imaplib.Time2Internaldate(time.time()),bytes(message))
		tmp_connection.close()
		tmp_connection.logout()


	def delete(self,num,messageid):
		self.transfer_messageid_lst.append(messageid)
		tmp_connection = imaplib.IMAP4_SSL(self.server_config["host"])
		tmp_connection.login(self.server_config["user"],self.server_config["password"])
		tmp_connection.select("INBOX",readonly=False)
		tmp_connection.store(num,'+FLAGS','\\Deleted')	
		tmp_connection.expunge()
		tmp_connection.close()
		tmp_connection.logout()


	def check_exist(self):
		line = self.connection.readline().strip()

		if "EXISTS" in line.decode("UTF-8"):
			num = line.decode("UTF-8").split(" ")[1]
			return True,num
		else:
			return False,None


	def exit(self):
		self.connection.close()
		self.connection.logout()
