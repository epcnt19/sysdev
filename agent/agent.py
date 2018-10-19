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
import virus_total_apis

from threading import Thread
from email.header import decode_header,make_header


imaplib.Debug = 4
server = "localhost"
user = ""
password = ""
detach_dir = "."
log_path = "/var/log/imapagent.log"


def open_connection():
	connection = imaplib.IMAP4_SSL(server)
	connection.login(user,password)
	return connection


def fetch_message(num):
	s = open_connection()
	s.select("INBOX",readonly=True)
	typ,data = s.fetch(num,"(RFC822)")
	s.logout()
	return typ,data
	

def write_attachments(filepath,payload):
	with open(filepath,"wb") as f:
		f.write(payload)
	f.close()


def write_log(message):
	with open(log_path,"a") as f:
		f.write(message)
	f.close()


def scan_attachments(filepath,thread1):
	thread1.join()

	result = ""
	response_scan = api.scan_file(filepath)
	file_hash = response_scan["results"]["sha1"]
	response_report = api.get_file_report(file_hash)
	json_dict = json.loads(json.dumps(response_report))
	
	for key,value in json_dict["results"].items():
			if key != "scans":
				result += "{0} : {1}\n".format(key,value)
	
	write_log(result)


def main():
	try:
		s = open_connection()
		s.select("INBOX",readonly=True)
			
		m = "{0} IDLE\r\n".format(s._new_tag().decode("UTF-8"))
		s.send(m.encode())

		while True:
			line  = s.readline().strip()

			if "EXISTS" in line.decode("UTF-8"):
				num = line.decode("UTF-8").split(" ")[1]
				typ,data = fetch_message(num)
					
				if typ != "OK":
					continue				

				mail_message = email.message_from_bytes(data[0][1])

				for part in mail_message.walk():
					if part.get_content_maintype() == "multipart":
						continue
					if part.get('Content-Disposition') is None:
						continue

					filname = part.get_filename()
						
					if bool(filname):
						filepath = os.path.join(detach_dir,'attachments',filname)
						if not os.path.isfile(filepath):
							write_log("attachments detect : {0}\n".format(filname))
							t1 = Thread(target=write_attachments,args=(filepath,part.get_payload(decode=True)))
							t1.daemon = True
							t1.start()

							write_log("start scan attachments : {0}\n".format(filname))
							t2 = Thread(target=scan_attachments,args=(filepath,t1))
							t2.daemon = True
							t2.start()

	finally:
		try:
			s.close()
		except:
			pass
		s.logout()


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
	parser.add_argument("--user",help="set IMAP user name")
	parser.add_argument("--password",help="set IMAP user password")
	parser.add_argument("--filepath",help="set saving attachments filepath")
	parser.add_argument("--apikey",help="set virustotal api key")	

	args = parser.parse_args()
	user = str(args.user)
	password = str(args.password)
	detach_dir = str(args.filepath)
	apikey = str(args.apikey)

	api = virus_total_apis.PublicApi(apikey)
	daemon()
