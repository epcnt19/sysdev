#coding:utf-8

import os
import sys
import imaplib
import email
import base64

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
	c = open_connection()
	c.select("INBOX",readonly=True)
	typ,data = c.fetch(num,"(RFC822)")
	c.logout()
	return typ,data
	

def write_attachments(filepath,payload):
	with open(filepath,"wb") as f:
		f.write(payload)
	f.close()


def main():
	try:
		c = open_connection()
		c.select("INBOX",readonly=True)
			
		m = "{0} IDLE\r\n".format(c._new_tag().decode("UTF-8"))
		c.send(m.encode())

		while True:
			line  = c.readline().strip()
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
			c.close()
		except:
			pass
		c.logout()


if __name__ == "__main__":
	main()