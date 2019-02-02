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

	if (filename is not None) and (attach_file is not None):
		msg.add_attachment(attach_file,maintype=mine['type'],subtype=mine['subtype'],filename=filename)
	
	return msg


def read_file(filepath):
	with open(filepath,"rb") as f:
		fr = f.read()
	return fr


def main():

	if filepath is not None:
		fr = read_file(filepath)
		fn = filepath.split("/")[-1]
		msg = create_message(from_addr,to_addr,subject,body,fn,fr)
	else:
		msg = create_message(from_addr,to_addr,subject,body,None,None)
		
	s = smtplib.SMTP(server,port)
	s.sendmail(from_addr,[to_addr],msg.as_string())
	s.close()
	

if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--faddr",help="set from addr",default=None)
	parser.add_argument("--taddr",help="set to addr",default=None)
	parser.add_argument("--subject",help="set subject text",default=None)
	parser.add_argument("--body",help="set body text",default=None)
	parser.add_argument("--filepath",help="set filepath",default=None)

	args = parser.parse_args()
	from_addr = args.faddr
	to_addr = args.taddr
	subject = args.subject
	body = args.body
	filepath = args.filepath
	mine = {'type':'text','subtype':'comma-separated-values'}

	main()
