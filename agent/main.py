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
from surface import SurfaceAnalysis

from threading import Thread
from email.header import decode_header,make_header


imaplib.Debug = 4
src_server = {"host":"localhost","user":"","password":""}
dst_server = {"host":"localhost","user":"","password":""}
detach_dir = "."
log_path = "/var/log/imapagent.log"


def write_attachments(filepath,payload):
	with open(filepath,"wb") as f:
		f.write(payload)
	f.close()


def write_log(message):
	with open(log_path,"a") as f:
		f.write(message)
	f.close()


def scan_attachments_vt(filepath,thread):
	thread.join()
	response_hash = api.scan(filepath)
	response_report = api.report(response_hash)
	write_log(response_report)


def scan_attachments_yara(filepath,thread):
	thread.join()
	detect_signatures = surface.yara(rulepath,filepath)
	write_log("detect {0} signature\n".format(str(len(detect_signatures))))
	
	result = ""
	for signature in detect_signatures:
		result += "{0}\n".format(signature)

	write_log(result)


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
								
						write_log("[*] start scanning attachments using VirusTotal : {0}\n".format(filename))
						t2 = Thread(target=scan_attachments_vt,args=(filepath,t1))
						t2.daemon = True
						t2.start()

						write_log("[*] start scanning attachments using Yara : {0}\n".format(filename))
						t3 = Thread(target=scan_attachments_yara,args=(filepath,t2))
						t3.deamon = True
						t3.start()

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
	parser.add_argument("--rulepath",help="set yara rule filepath")

	args = parser.parse_args()
	
	src_server["user"] = str(args.src_user)
	src_server["password"] = str(args.src_password)
	dst_server["user"] = str(args.dst_user)
	dst_server["password"] = str(args.dst_password)

	detach_dir = str(args.filepath)
	apikey = str(args.apikey)
	rulepath = str(args.rulepath)
	
	api = Virustotal(apikey)
	surface = SurfaceAnalysis()

	daemon()
