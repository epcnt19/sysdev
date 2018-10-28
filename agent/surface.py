#coding:utf-8
import yara
import argparse
import magic
import pefile

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


	def scan_iat(self,binpath):
		dll_dist = {}
		pe = pefile.PE(binpath,fast_load=True)
		pe.parse_data_directories()

		for entry in pe.DIRECTORY_ENTRY_IMPORT:
			dll_lst = []

			for imp in entry.imports:
				if imp.name is not None:
					dll_lst.append(imp.name)

			dll_dist.update({entry.dll:dll_lst})
		
		return dll_dist
