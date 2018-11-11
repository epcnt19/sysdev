#coding:utf-8

import virus_total_apis
import json


class Virustotal:
	
	def __init__(self,apikey):
		self.api = virus_total_apis.PublicApi(apikey)

	def scan(self,filepath):
		response_scan = self.api.scan_file(filepath)
		filehash = response_scan["results"]["sha1"]
		return filehash

	def report(self,filehash):
		result = {}
		response_report = self.api.get_file_report(filehash)
		json_dict = json.loads(json.dumps(response_report))

		for key,value in json_dict["results"].items():
			if key != "scans":
				result.update({key:value})
		
		return result
