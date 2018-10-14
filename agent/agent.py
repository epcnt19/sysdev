#coding:utf-8

import os
import sys
import imaplib
import email
import base64
import argparse

from threading import Thread
from email.header import decode_header,make_header


imaplib.Debug = 4
server = "localhost"
user = ""
password = ""
detach_dir = "."


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


def main():
	try:
		s = open_connection()
		s.select("INBOX",readonly=True)
			
		m = "{0} IDLE\r\n".format(s._new_tag().decode("UTF-8"))
		s.send(m.encode())

		while True:
			line  = s.readline().strip()
			print(line)	

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
							# print("attachments detect : {0}".format(filname))
							t = Thread(target=write_attachments,args=(filepath,part.get_payload(decode=True)))
							t.daemon = True
							t.start()

	finally:
		try:
			s.close()
		except:
			pass
		s.logout()


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--user",help="set IMAP user name")
	parser.add_argument("--password",help="set IMAP user password")
	parser.add_argument("--filepath",help="save attachments filepath")
	
	args = parser.parse_args()
	user = str(args.user)
	password = str(args.password)
	detach_dir = str(args.filepath)
	main()
