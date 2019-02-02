#coding:utf-8
import configparser


def main():
	config = configparser.ConfigParser()
	config.read("config.ini")
	
	print(config["AGENT"]["src_user"])
	print(config["AGENT"]["src_password"])

if __name__ == "__main__":
	main()
