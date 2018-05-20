#ord(A) -> asci to returns assic 
#bin(17) -> returns binary

#   DDDDD   NN   NN  SSSSS      SSSSS
#   DD  DD  NNN  NN SS         SS        eee  rr rr  vv   vv   eee  rr rr
#   DD   DD NN N NN  SSSSS      SSSSS  ee   e rrr  r  vv vv  ee   e rrr  r
#   DD   DD NN  NNN      SS         SS eeeee  rr       vvv   eeeee  rr
#   DDDDDD  NN   NN  SSSSS      SSSSS   eeeee rr        v     eeeee rr

#   All DNS packets have a structure that is
#   +---------------------+
#   |       Header        |
#   +---------------------+
#   |      Question       | Question for the name server
#   +---------------------+
#   |      Answer         | Answers to the question
#   +---------------------+
#   |      Authority      | Not used in this project
#   +---------------------+
#   |      Additional     | Not used in this project
#   +---------------------+


# Useful link summarizing the description of all the fields
#  https://www2.cs.duke.edu/courses/fall16/compsci356/DNS/DNS-primer.pdf

#import socket
from socket import *
import codecs
import glob
import json

#Declare the port and ipaddress of your DNS Server
ip = '127.0.0.1'
port = 53
servername = "Isaac's Server"

#Setup the Sockets.
sock = socket(AF_INET, SOCK_DGRAM)
sock.bind((ip, port))

#all domains found in zone/ directory
domains = []

#parsed stuff to share
globals = {
	"QTYPE" : '',
	"domainindex" : None
	}

#convert str ip to hex ip
def hexifyip(ip):
	hexip = b''
	
	if '.' in ip:
		for part in ip.split('.'):
			hexip += bytes([int(part)])

	else:
		for part in ip.split(':'):
			hexip += int(part, 16).to_bytes(2, byteorder='big')
		
	return(hexip)

#convert domain from str to hex by DNS standard
def hexifydomain(domain):
	startpos = 0
	endpos = -1
	hexdomain = b''
	
	while True:
		endpos = domain.find('.', endpos + 1)
		if endpos == -1:
			hexdomain += (len(domain[startpos:])).to_bytes(1, byteorder='big')
			for c in domain[startpos:]:
				hexdomain += ord(c).to_bytes(1, byteorder='big')
			break
		hexdomain += (len(domain[startpos:endpos])).to_bytes(1, byteorder='big')
		for c in domain[startpos:endpos]:
			hexdomain += ord(c).to_bytes(1, byteorder='big')
		startpos = endpos + 1
	
	hexdomain += b'\x00'
	
	return(hexdomain)
	
#convert domain from hex to str by DNS standard
def unhexifydomain(domainhex):
	domain = ''
	index = 0
	
	while True:
		for i in range(index + 1, int(domainhex[index]) + index + 1):
			domain += domainhex[i:(i+1)].decode('utf-8')
			#print(domain, i)
		
		domainhex[i:(i+1)]
		index += int(domainhex[index] + 1)
		if domainhex[index] == 0:
			break
		
		domain += '.'
	
	return domain

#load all domains into memory
def getdomains():
	#!glob returns in windows is different from linux!
	#remove 'zone/' path and '.zone' extention to avoid this ^
	for file in glob.glob("zones/*.zone"): 
		if '.zone' in file:
			domains.append(file[6:-5])
	
#get the index of end bit of domain in data
def getquestiondomain(data):	
	expectedlength = int(data[0])
	domainstring = ''
	domainparts = []
	j = 0 #start of domainstring index

	while expectedlength != 0:
		for i in range(j, j + expectedlength):
			domainstring += str(data[i+1])
			j+=1
		expectedlength = int(data[j+1])
		j+=1
		domainparts.append(domainstring)
		domainstring = ''
	
	j+=1
	return (j)
	
#Helper funcitons
def asciiToBinary(message):
	binary = ""
	hexString = ""
	for i in message:
		hexString += hex(ord(i)) + " "
		bits = bin(ord(i))[2:].zfill(8)
		binary += bits
	#  print(hexString)
	return binary

def BinaryToAscii(binary):
	hexP = b''
	hexString = ''
	for i in range(0, len(binary), 8):
		hexP += int((binary[i: i + 8]), 2).to_bytes(1, byteorder='big')
		hexString += hex(int((binary[i: i + 8]), 2)) + " "
	#print(hexString)
	#print(hexP)
	return hexP

#All DNS Packets have a headers

#                                 1  1  1  1  1  1
#   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     ID                        |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |QR|  Opcode   |AA|TC|RD|RA|   Z    | RCODE     |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     QDCOUNT                   |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     ANCOUNT                   |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     NSCOUNT                   |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                     ARCOUNT                   |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#Parse and build header
def parseheader(data):
	globals["domainindex"] = getquestiondomain(data[12:]) + 12
	
	#QTYPE
	if data[globals["domainindex"]: globals["domainindex"]+2] == b'\x00\x1c':
		globals["QTYPE"] = 'AAAA'
	
	elif data[globals["domainindex"]: globals["domainindex"]+2] == b'\x00\x01':
		globals["QTYPE"] = 'A'
	
	#future use
	#elif data[globals["domainindex"]: globals["domainindex"]+2] == b'\x00\x0c':
	#	globals["QTYPE"] = 'PTR'
	
	else:
		globals["QTYPE"] = 'Unknown'

	
def buildheader(data, numanswers):
	
	#Transaction id
	header = data[:2]	

	#Flags
	if numanswers > 0:
		#b'1 0000 0 0 1 1 000 0000' standard query reponse
		header += b'\x81\x80'
	else:
		#b'1 0000 0 0 1 1 000 0011' Name Error (domain not found)
		header += b'\x81\x83'
	
	#QDCount
	header += b'\x00\x01'
	
	#ANCOUNT
	header += numanswers.to_bytes(2, byteorder='big')

	#NSCOUNT
	header += b'\x00\x00'
	
	#ARCOUNT
	header += b'\x00\x00'
	
	return header
	
#                                  1  1  1  1  1  1
#    0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                                                |
#   /                    QNAME                       /
#   /                                                /
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                    QTYPE                      |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#   |                    QCLASS                     |
#   +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

#data[12:]
def buildquestion(data):
	
	#QNAME
	question = data[12: globals["domainindex"]]
	
	#QTYPE
	question += data[globals["domainindex"]: globals["domainindex"]+2]
	
	#QCLASS
	question += b'\x00\x01'
	
	return question

#                                    1  1  1  1  1  1
#      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                                               |
#    /                                               /
#    /                      NAME                     /
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TYPE                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                     CLASS                     |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                      TTL                      |
#    |                                               |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
#    |                   RDLENGTH                    |
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
#    /                     RDATA                     /
#    /                                               /
#    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+


def buildanswer(data):	
	numanswers = 0
	answer = b''
	domain = unhexifydomain(data[12: globals["domainindex"]])
	print("Query: " + domain)
	
	#Future use
	#if globals["QTYPE"] == 'PTR':
	#	print('PTR: ' + servername)
	#	answer += b'\xc0\x0c' #NAME
	#	answer += data[globals["domainindex"]: globals["domainindex"]+2] #TYPE
	#	answer += b'\x00\x01' 	#CLASS
	#	answer += b'\x00\x00\x02\x58' #TIL (600 seconds)
	#	answer += len(servername).to_bytes(2, byteorder='big') #RDLENGTH
	#	for c in servername:
	#		answer += ord(c).to_bytes(1, byteorder='big') #RDATA
	
	#elif
	if domain in domains and globals["QTYPE"] != 'Unknown':
		filepath = 'zones/' + domain + '.zone'
		with open(filepath) as f:
			zonedata = json.load(f)
			
			numanswers = len(zonedata[globals["QTYPE"]])
			if numanswers > 0:
				for ip in zonedata[globals["QTYPE"]]:
					print(ip)
					answer += b'\xc0\x0c' #NAME (pointer to addr in header)
					answer += data[globals["domainindex"]: globals["domainindex"]+2] #TYPE (0001->A, 001c->AAAA, 000c->PTR 0005->CNAME)
					answer += b'\x00\x01' #CLASS
					answer += b'\x00\x00\x02\x58' #TIL (600 seconds)
					
					if globals["QTYPE"] == 'A':
						answer += b'\x00\x04' #RDLENGTH
						answer += hexifyip(ip) #RDATA
					elif globals["QTYPE"] == 'AAAA':
						answer += b'\x00\x10' #RDLENGTH
						answer += hexifyip(ip) #RDATA
					else:
						answer += b'\x00\x00'
										
			else:
				print('No ip found')
				
	else: 
		print('domain not found')
	
	return answer, numanswers
	

#Construct the final response packet 
def buildresponse(data):
	question = buildquestion(data)
	answer, numanswers = buildanswer(data)
	header = buildheader(data, numanswers)
	
	response = header
	response += question
	response += answer
	
	#print(response)
	return response

#initialize and listen
getdomains()
print("Server Ready")
while 1: 
	data, addr = sock.recvfrom(512)
	print()
	print('Connection recieved')
	print(data)
	parseheader(data)
	r = buildresponse(data)
	sock.sendto(r, addr)

