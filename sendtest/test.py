#coding:utf-8

import smtplib
import argparse
import mimetypes
from email.message import EmailMessage
from email.policy import SMTP


server = "127.0.0.1"
port = 25


def create_message(from_addr,to_addr,subject,body,filename,attach_file):
	msg = EmailMessage()
	msg["Subject"] = subject
	msg["From"] = from_addr
	msg["To"] = to_addr
	msg.set_content(body)
	msg.add_attachment(attach_file,maintype=mine['type'],subtype=mine['subtype'],filename=filename)
	return msg


def read_file(filepath):
	with open(filepath,"rb") as f:
		fr = f.read()
	return fr


def main():
	fr = read_file(filepath)
	fn = filepath.split("/")[-1]
	
	msg = create_message(from_addr,to_addr,subject,body,fn,fr)
	s = smtplib.SMTP(server,port)
	s.sendmail(from_addr,[to_addr],msg.as_string())
	s.close()
	

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--faddr",help="set from addr")
	parser.add_argument("--taddr",help="set to addr")
	parser.add_argument("--subject",help="set subject text")
	parser.add_argument("--body",help="set body text")
	parser.add_argument("--filepath",help="set filepath")

	args = parser.parse_args()
	from_addr = args.faddr
	to_addr = args.taddr
	subject = args.subject
	body = args.body
	filepath = args.filepath
	mine = {'type':'text','subtype':'comma-separated-values'}

	main()
