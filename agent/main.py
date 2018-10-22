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
from agent import Agent

from threading import Thread
from email.header import decode_header,make_header


imaplib.Debug = 4
src_server = {"host":"localhost","user":"","password":""}
dst_server = {"host":"localhost","user":"","password":""}
detach_dir = "."
log_path = "/var/log/imapagent.log"
transfer_messageid_lst = []


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
		src = Agent(src_server["user"],src_server["password"],src_server["host"])
		dst = Agent(dst_server["user"],dst_server["password"],dst_server["host"])

		while True:
			exist,num = src.check_exist()

			if exist:
				typ,data = src.fetch(num)
				if typ != "OK":
					continue

				for part in email.message_from_bytes(data[0][1]).walk():
					if part.get_content_maintype() == "multipart":
						continue
						
					if part.get('Content-Disposition') is None:
						continue

					filename = part.get_filename()

					if bool(filename):
						write_log("[*] attachments detect : {0}\n".format(filename))
						filepath = os.path.join(detach_dir,'attachments',filename)
							
						write_log("[*] start transfer message to receiver\n")
						dst.append(email.message_from_bytes(data[0][1]))
							
						write_log("[*] delete message from INBOX\n")
						src.delete(num,email.message_from_bytes(data[0][1])['Message-ID'])
						
						write_log("[*] start writing attachments : {0}\n".format(filename))
						t1 = Thread(target=write_attachments,args=(filepath,part.get_payload(decode=True)))
						t1.daemon = True
						t1.start()
								
						write_log("[*] start scaning attachments : {0}\n".format(filename))
						t2 = Thread(target=scan_attachments,args=(filepath,t1))
						t2.daemon = True
						t2.start()

	finally:
		try:
			src.exit()
			dst.exit()
		except:
			pass


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
