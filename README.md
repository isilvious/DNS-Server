DNS-Server

includes
	DNSserver.py
	zonebuilder.py
	
This is a DNS server that only uses a UDP connection type and can only answer simple IPv4 and IPv6 queries. This server uses .zone files to store domain data in JSON format. zonebuilder.py is included so the user can easily add their own domains to the zones folder. The server, however, does not support any domains outside of the zones folder, i.e. to access isilvious.com, you must make a .zones file using the correct IP. While this sounds silly at first, this allows the user to set up their own websites that only users on the network can access. USAGE: download and install python 3, set serverAddress to your current IP, run server, set the default DNS on any computer on the network to the IP of the DNS server, wait a minute and restart and open browsers, use browser as usual. 

Bugs: zonebuilder.py does NOT check to see if you entered a valid IP . Invalid IPs can crash the DNS server!