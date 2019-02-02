#coding:utf-8
import re
import sys
import time
import subprocess
import shutil


def get_cmd_result(cmd,trace_time):
	process = subprocess.Popen(cmd,shell=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
	start_time = time.time()	

	while True:
		line = process.stdout.readline()
		
		if line:
			yield line
		if not line and process.poll() is not None:
			process.terminate()
			break
		
		elapsed_time = time.time() - start_time

		if elapsed_time > trace_time:
			process.terminate()
			break
		

class DynamicAnalysis:
	host_cmd_dict = {"domain_to_id":"xl domid {0}","get_pid":"vmi-process-list {0} | grep {1}"}
	
	guest_cmd_dict = {"download":"cmd.exe /c \\\"ping -n 5 127.0.0.1 && powershell (new-object System.Net.WebClient).Downloadfile(\'http://10.0.0.3/file/{0}\', \'C:\\\\Users\\\\test\\\\Desktop\\\\example.exe\')\\\"","injector":"injector -r {0} -d {1} -i {2} -e \"{3}\"","drakvuf":"drakvuf -r {0} -d {1} -i {2} -e \"{3}\" -T {4}"}

	execute_path = "C:\\\\Users\\\\test\\\\Desktop\\\\example.exe"

	def __init__(self):
		pass

	def copy_file(self,binpath,docroot):
		self.sample_name = binpath.split("/")[-1]
		shutil.copy2(binpath,docroot)
		
	def scan_drakvuf(self,domain_name,process_name,rekall_path,tcpip_path,trace_time):
		domain_id = subprocess.getoutput(self.host_cmd_dict["domain_to_id"].format(domain_name))
		process_id_re = subprocess.getoutput(self.host_cmd_dict["get_pid"].format(domain_name,process_name))
		pattern = r"\[.*\]"
		process_id = str(int(re.search(pattern,process_id_re).group().replace("[","").replace("]","")))
		injector_trace_time = 60
		drakvuf_trace_time = trace_time
		result = ""

		injector = self.guest_cmd_dict["injector"].format(rekall_path,domain_id,process_id,self.guest_cmd_dict["download"].format(self.sample_name))
		print(injector)

		for line in get_cmd_result(injector,injector_trace_time):
			print(line)

		time.sleep(10)

		drakvuf = self.guest_cmd_dict["drakvuf"].format(rekall_path,domain_id,process_id,self.execute_path,tcpip_path)
		print(drakvuf)
		
		for line in get_cmd_result(drakvuf,drakvuf_trace_time):
			result += line.decode("utf-8","replace")

		return result
