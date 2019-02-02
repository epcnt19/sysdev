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
import smtplib
import configparser

from vt import Virustotal
from agent import Agent
from surface import SurfaceAnalysis
from dynamic import DynamicAnalysis
from threading import Thread
from datetime import datetime
from email.header import decode_header,make_header
from email.message import EmailMessage
from email.policy import SMTP
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.utils import COMMASPACE,formatdate
from email import encoders


imaplib.Debug = 4
src_server = {"host":"localhost","port":"","user":"","password":""}
dst_server = {"host":"localhost","port":"","user":"","password":""}

detect_mail_subject = "Detect Malware"
detect_mail_from = "master@analyze"
detect_mail_body_fmt = "Date \n\t{0}\nSubject \n\t{1}\nFilename \n\t{2}\nFiletype \n\t{3}\nYara Signatures \n{4}\nDLLs \n{5}\nVirusTotal URL \n\t{6}\n"


def write_attachments(filepath,payload):
	with open(filepath,"wb") as f:
		f.write(payload)
	f.close()


def write_log(message):
	with open(log_path,"a") as f:
		f.write(message)
	f.close()


def scan_attachments_vt(filepath,q):
	response_hash = api.scan(filepath)
	response_dict = api.report(response_hash)

	if(response_dict["response_code"] == -2):
		evaluation_value = 0.0
		scan_date = ""
		sha_256 = ""
		url = ""
	else:
		evaluation_value = int(response_dict["positives"])*1.0 / int(response_dict['total'])*1.0
		scan_date = response_dict["scan_date"]
		sha_256 = response_dict["sha256"]
		url = response_dict["permalink"]

	q_dist =  {"evaluation_value":evaluation_value,"scan_date":scan_date,"sha256":sha_256,"url":url}
	q.put(q_dist)


def scan_attachments_surface(filepath,q):
	filetype = surface.scan_filetype(filepath)
	write_log("filetype : {0}\n".format(filetype))

	detect_signatures = surface.scan_yara(rule_path,filepath)
	write_log("detect {0} signature\n".format(str(len(detect_signatures))))

	signature_result = ""

	for signature in detect_signatures:
		signature_result += "\t{0}\n".format(signature)
		
	write_log(signature_result)

	if "PE32 executable" in filetype:
		detect_apis = surface.scan_iat(filepath)
		write_log("detect {0} DLLs\n".format(len(detect_apis.keys())))

		dll_result = ""

		for dll,apis in detect_apis.items():
			dll_result += "\t{0}\n".format(dll.decode("utf-8"))
			api_result = ""			

			for api in apis:
				api_result += "\t\t{0}\n".format(api.decode("utf-8"))
			
			dll_result += api_result

		write_log(dll_result)

	q_dist = {"filetype":filetype,"signature":signature_result,"dll":dll_result}
	q.put(q_dist)


def scan_attachments_dynamic(filepath,q,):
	dynamic.copy_file(filepath,document_path)
	result = dynamic.scan_drakvuf(domain_name,process_name,rekall_path,tcpip_path,trace_time).encode(encoding="utf-8")
	q.put(result)
		

def send_mail(mail_raw,url,filetype,signature,dll,trace_filepath):
	header_from = mail_raw.get("From")
	header_to = mail_raw.get("To")
	header_subject = mail_raw.get("Subject")
	header_date = mail_raw.get("Date")							

	body = mail_raw.get_payload()				
	body_text = body[0].get_payload()
	body_filename = body[1].get("Content-Disposition").split(" ")[1].split("filename=")[1]
	detect_mail_body = detect_mail_body_fmt.format(header_date,header_subject,body_filename,filetype,signature,dll,url)

	# msg = EmailMessage()
	msg = MIMEMultipart()
	msg["Subject"] = detect_mail_subject
	msg["From"] = detect_mail_from
	msg["To"] = header_to
	msg["Detect"] = "True"
	msg.attach(MIMEText(detect_mail_body))

	part = MIMEBase("application","octet-stream")
	part.set_payload(open(trace_filepath,"rb").read())
	encoders.encode_base64(part)
	part.add_header("Content-Disposition","attachment; filename=\"{0}\"".format(trace_filepath.split("/")[-1]))	
	msg.attach(part)

	s = smtplib.SMTP(src_server["host"],src_server["port"])
	s.sendmail(detect_mail_from,[header_to],msg.as_string())
	s.close()


def main():
	try:
		src = Agent(src_server["user"],src_server["password"],src_server["host"])
		dst = Agent(dst_server["user"],dst_server["password"],dst_server["host"])

		while True:
			exist,num = src.check_exist()

			if exist:
				typ,data = src.fetch(num)
				mail_raw = email.message_from_bytes(data[0][1])

				typ_flagged,data_flagged = src.search("Flagged")
				flagged_lst = [num.decode("utf-8") for num in data_flagged[0].split()]

				if num in flagged_lst:
					continue

				if typ != "OK":
					continue

				if mail_raw["Detect"] is not None:
					continue

				for part in mail_raw.walk():
					if part.get_content_maintype() == "multipart":
						continue
				
					if part.get("Content-Disposition") is None:
						continue

					filename = part.get_filename()

					if bool(filename):
						write_log("[*] attachments detect : {0}\n".format(filename))
						filepath = os.path.join(detach_dir,"attachments",filename)
						
						# transfer other user's mailbox
						# write_log("[*] start transfer message to receiver\n")
						# dst.append(mail_raw,"")
							
						write_log("[*] delete message from INBOX\n")
						src.delete(num,mail_raw["Message-ID"])
						
						write_log("[*] start writing attachments : {0}\n".format(filename))
						write_attachments(filepath,part.get_payload(decode=True))
								
						write_log("[*] start scanning attachments using VirusTotal : {0}\n".format(filename))
						scan_attachments_vt(filepath,q)

						q_dist = q.get()
						evaluation_value = q_dist["evaluation_value"]
						scan_date = q_dist["scan_date"]
						sha256 = q_dist["sha256"]
						url = q_dist["url"]								
			
						write_log("[*] evaluation_value : {0} : {1}\n".format(str(evaluation_value),filename))

						if evaluation_value > 0.00:
							write_log("[*] detect malicious : {0}\n".format(filename))
							write_log("[*] start scanning attachments using surface analysis : {0}\n".format(filename))
							scan_attachments_surface(filepath,q)

							q_dist = q.get()
							filetype = q_dist["filetype"]
							signature = q_dist["signature"]
							dll = q_dist["dll"]

							write_log("[*] start scanning attachments using dynamic analysis : {0}\n".format(filename))
							scan_attachments_dynamic(filepath,q)

							trace_result = q.get()
							write_log("[*] start writing trace log\n")
							trace_filepath = os.path.join(detach_dir,"tracelog",datetime.now().strftime("%Y%m%d%H%M%S.log"))
							write_attachments(trace_filepath,trace_result)

							send_mail(mail_raw,url,filetype,signature,dll,trace_filepath)
						else:
							write_log("[*] undetect malicious : {0}\n".format(filename))
							write_log("[*] start appending mail added \\Flagged")
							src.append(mail_raw,"\\Flagged")
							
	finally:
		try:
			src.exit()
			dst.exit()
		except:
			pass


def daemon():
	"""
	sys.stdout = open(log_path,"a")
	sys.stderr = open(log_path,"a")

	pid = os.fork()
	
	if pid > 0:
		sys.exit()

	if pid == 0:
		main()
	"""

	main()


if __name__ == "__main__":
	config = configparser.ConfigParser()
	parser = argparse.ArgumentParser()
	parser.add_argument("--config",help="set config filepath")
	args = parser.parse_args()
	config_path = str(args.config)
	config.read(config_path)
	
	src_server["user"] = str(config["AGENT"]["src_user"])
	src_server["password"] = str(config["AGENT"]["src_password"])
	src_server["host"] = str(config["AGENT"]["src_server_ip"])
	src_server["port"] = str(config["AGENT"]["src_server_port"])

	dst_server["user"] = str(config["AGENT"]["dst_user"])
	dst_server["password"] = str(config["AGENT"]["dst_password"])
	dst_server["host"] = str(config["AGENT"]["dst_server_ip"])
	dst_server["port"] = str(config["AGENT"]["dst_server_port"])

	detach_dir = str(config["ATTACHMENT"]["file_path"])
	apikey = str(config["VIRUSTOTAL"]["apikey"])
	rule_path = str(config["YARA"]["rule_path"])
	log_path = str(config["LOG"]["log_path"])

	domain_name = str(config["DRAKVUF"]["domain_name"])
	process_name = str(config["DRAKVUF"]["process_name"])
	rekall_path = str(config["DRAKVUF"]["rekall_path"])
	tcpip_path = str(config["DRAKVUF"]["tcpip_path"])
	document_path = str(config["DRAKVUF"]["document_path"])
	trace_time = int(config["DRAKVUF"]["trace_time"])

	api = Virustotal(apikey)
	surface = SurfaceAnalysis()
	dynamic = DynamicAnalysis()
	q = queue.Queue()

	daemon()
