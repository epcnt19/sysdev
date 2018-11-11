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
import queue

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


def scan_attachments_vt(filepath,q,thread):
	thread.join()
	response_hash = api.scan(filepath)
	response_dict = api.report(response_hash)
	
	print(response_dict)
	evaluation_value = int(response_dict['positives'])*1.0 / int(response_dict['total'])*1.0
	scan_date = response_dict['scan_date']
	sha_256 = response_dict['sha256']
	url = response_dict['permalink']

	q_dist =  {"evaluation_value":evaluation_value,"scan_date":scan_date,"sha256":sha_256,"url":url}

	"""
	for key,value in response_dict.items():
		write_log("{0}:{1}\n".format(key,value))
	"""

	q.put(q_dist)


def scan_attachments_surface(filepath,thread):
	thread.join()

	filetype = surface.scan_filetype(filepath)
	write_log("filetype : {0}\n".format(filetype))
	
	detect_signatures = surface.scan_yara(rulepath,filepath)
	write_log("detect {0} signature\n".format(str(len(detect_signatures))))

	result = ""
	for signature in detect_signatures:
		result += "{0}\n".format(signature)

	write_log(result)

	if "PE32 executable" in filetype:
		detect_apis = surface.scan_iat(filepath)
		write_log("detect {0} DLLs\n".format(len(detect_apis.keys())))

		result = ""
		for dll,apis in detect_apis.items():
			result += "{0}\n".format(dll.decode("utf-8"))

			for api in apis:
				result += "\t{0}\n".format(api.decode("utf-8"))

		write_log(result)


def main():
	try:
		src = Agent(src_server["user"],src_server["password"],src_server["host"])
		dst = Agent(dst_server["user"],dst_server["password"],dst_server["host"])

		while True:
			exist,num = src.check_exist()

			if exist:
				typ,data = src.fetch(num)
				typ_flagged,data_flagged = src.search('Flagged')
				flagged_lst = [num.decode('utf-8') for num in data_flagged[0].split()]

				if num in flagged_lst:
					continue

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
						
						# transfer other user's mailbox
						# write_log("[*] start transfer message to receiver\n")
						# dst.append(email.message_from_bytes(data[0][1]),"")
							
						write_log("[*] delete message from INBOX\n")
						src.delete(num,email.message_from_bytes(data[0][1])['Message-ID'])
						
						write_log("[*] start writing attachments : {0}\n".format(filename))
						t1 = Thread(target=write_attachments,args=(filepath,part.get_payload(decode=True)))
						t1.daemon = True
						t1.start()
								
						write_log("[*] start scanning attachments using VirusTotal : {0}\n".format(filename))
						t2 = Thread(target=scan_attachments_vt,args=(filepath,q,t1))
						t2.daemon = True
						t2.start()

						# detect malicious
						t2.join()
						q_dist = q.get()
						evaluation_value = q_dist['evaluation_value']
						scan_date = q_dist['scan_date']
						sha256 = q_dist['sha256']
						url = q_dist['url']								
			
						write_log("[*] evaluation_value : {0} : {1}\n".format(str(evaluation_value),filename))

						if evaluation_value > 0.50:
							write_log("[*] detect malicious : {0}\n".format(filename))
							write_log("[*] start scanning attachments using surface analysis : {0}\n".format(filename))
							t3 = Thread(target=scan_attachments_surface,args=(filepath,t2))
							t3.deamon = True
							t3.start()
						else:
							write_log("[*] undetect malicious : {0}\n".format(filename))
							write_log("[*] start appending mail added \\Flagged")
							src.append(email.message_from_bytes(data[0][1]),"\\Flagged")
							
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
	q = queue.Queue()

	# daemon()
	main()
