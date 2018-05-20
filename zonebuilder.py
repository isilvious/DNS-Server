import json
import os

def buildnew():
	#Get zone file data
	domain = input("Domain: ")
	filepath = 'zones/' + domain + '.zone'
	A = []
	AAAA = []
	
	while True:
		serverip = input("Server IPv4 (last IP should be 0 or Null): ")
		if serverip == '0' or serverip == '':
			break
		A.append(serverip)
	
	while True:
		serverip = input("Server IPv6 (last IP should be 0 or Null): ")
		if serverip == '0' or serverip == '':
			break
		AAAA.append(serverip)
	
	#Build JSON
	jsoninfo = json.dumps({'domain': domain, 'A': A, 'AAAA': AAAA}, indent=4, separators=(',', ': '))
	
	#Write JSON
	directory = os.path.dirname(filepath)
	if not os.path.exists(directory):
		os.makedirs(directory)
	
	f = open(filepath, "w+")
	f.write(jsoninfo)
	
inp = 'y'
while inp.lower() == 'y':
	buildnew()
	
	while True:
		inp = input("Create new zone? (Y/N): ")
		if inp.lower() == 'y' or inp.lower() == 'n':
			break