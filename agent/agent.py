#coding:utf-8

import os
import sys
import time
import imaplib
import email
import base64
import json
import argparse
import requests
import hashlib

from vt import Virustotal
from threading import Thread
from email.header import decode_header,make_header


imaplib.Debug = 4
src_server = {"host":"localhost","user":"","password":""}
dst_server = {"host":"localhost","user":"","password":""}
detach_dir = "."
log_path = "/var/log/imapagent.log"
transfer_messageid_lst = []


def open_connection(server):
	connection = imaplib.IMAP4_SSL(server["host"])
	connection.login(server["user"],server["password"])
	return connection


def fetch_message(num,server):
	session = open_connection(server)
	session.select("INBOX",readonly=True)
	typ,data = session.fetch(num,"(RFC822)")
	session.logout()
	return typ,data


def transfer_message(message,server):
	# write_log(str(type(message)))
	# write_log(str(bytes(message)))
	session = open_connection(server)
	session.append("INBOX","",imaplib.Time2Internaldate(time.time()),bytes(message))
	session.logout()


def delete_message(num,messageid,server):
	transfer_messageid_lst.append(messageid)
	session = open_connection(server)
	session.select("INBOX",readonly=False)
	session.store(num,'+FLAGS','\\Deleted')
	session.expunge()
	session.logout()
	

def write_attachments(filepath,payload):
	with open(filepath,"wb") as f:
		f.write(payload)
	f.close()


def write_log(message):
	with open(log_path,"a") as f:
		f.write(message)
	f.close()


def scan_attachments(filepath,thread):
	thread.join()
	response_hash = api.scan(filepath)
	response_report = api.report(response_hash)
	write_log(response_report)


def main():
	try:
		src_session = open_connection(src_server)
		src_session.select("INBOX")			

		idle_command = "{0} IDLE\r\n".format(src_session._new_tag().decode("UTF-8"))
		src_session.send(idle_command.encode())

		while True:
			line = src_session.readline().strip()

			if "EXISTS" in line.decode("UTF-8"):
				num = line.decode("UTF-8").split(" ")[1]
				typ,data = fetch_message(num,src_server)
					
				if typ != "OK":
					continue				

				for part in email.message_from_bytes(data[0][1]).walk():
					if part.get_content_maintype() == "multipart":
						continue
					if part.get('Content-Disposition') is None:
						continue

					filname = part.get_filename()

					if bool(filname):
						write_log("[*] attachments detect : {0}\n".format(filname))
						filepath = os.path.join(detach_dir,'attachments',filname)
						
						write_log("[*] start transfer message to receiver\n")
						transfer_message(email.message_from_bytes(data[0][1]),dst_server)
						
						write_log("[*] delete message from INBOX\n")
						delete_message(num,email.message_from_bytes(data[0][1])['Message-ID'],src_server)

						write_log("[*] start writing attachments : {0}\n".format(filname))
						t1 = Thread(target=write_attachments,args=(filepath,part.get_payload(decode=True)))
						t1.daemon = True
						t1.start()
						
						write_log("[*] start scaning attachments : {0}\n".format(filname))
						t2 = Thread(target=scan_attachments,args=(filepath,t1))
						t2.daemon = True
						t2.start()

	finally:
		try:
			src_session.close()
		except:
			pass
		src_session.logout()


def daemon():
	sys.stdout = open(log_path,"a")
	sys.stderr = open(log_path,"a")

	pid = os.fork()
	
	if pid > 0:
		sys.exit()

	if pid == 0:
		main()


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--src_user",help="set source IMAP user name")
	parser.add_argument("--src_password",help="set source IMAP user password")
	parser.add_argument("--dst_user",help="set destination IMAP user name")
	parser.add_argument("--dst_password",help="set destination IMAP user password")
	parser.add_argument("--filepath",help="set saving attachments filepath")
	parser.add_argument("--apikey",help="set virustotal api key")	

	args = parser.parse_args()
	
	src_server["user"] = str(args.src_user)
	src_server["password"] = str(args.src_password)
	dst_server["user"] = str(args.dst_user)
	dst_server["password"] = str(args.dst_password)

	detach_dir = str(args.filepath)
	apikey = str(args.apikey)

	api = Virustotal(apikey)
	daemon()
