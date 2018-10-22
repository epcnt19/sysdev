#coding:utf-8
import yara
import argparse
import hashlib


def main(rulepath,binpath):
	# binary = read_file(binpath,"rb")
	# binary_hash = hashlib.sha256(binary).hexdigest()
	rules = yara.compile(filepath=rulepath)
	matches = rules.match(data=open(binpath,"rb").read())
	
	for match in matches:
		print(str(match))


if __name__ == "__main__":
	parser = argparse.ArgumentParser()
	parser.add_argument("--rulepath",help="set input rule path")
	parser.add_argument("--binpath",help="set input binary path")

	args = parser.parse_args()
	rulepath = str(args.rulepath)
	binpath = str(args.binpath)

	main(rulepath,binpath)
