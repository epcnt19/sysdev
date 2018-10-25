#coding:utf-8
import yara
import argparse
import magic

class SurfaceAnalysis:
	def __init__(self):
		pass


	def scan_filetype(self,binpath):
		filetype = magic.from_file(binpath)
		return filetype


	def scan_yara(self,rulepath,binpath):
		rules = yara.compile(filepath=rulepath)
		matches = rules.match(data=open(binpath,"rb").read())
		detect_signature = [match for match in matches]
		return detect_signature
