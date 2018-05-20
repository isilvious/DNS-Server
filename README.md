DNS-Server

includes:
DNSserver.py
zonebuilder.py
	
This is a DNS server that only uses a UDP connection type and can only answer simple IPv4 and IPv6 queries. This server uses .zone files to store domain data in JSON format. zonebuilder.py is included so the user can easily add their own domains to the zones folder. The server, however, does not support any domains outside of the zones folder, i.e. to access isilvious.com, you must make a .zones file using the correct IP. While this sounds silly at first, this allows the user to set up their own websites that only users on the network can access. 

USAGE: To use this DNS server, it can be run either locally or on a seperate, host computer. If you are running this on a LAN, make sure the host computer has a static IP.
1. Download and install python 3
2. In the code, set serverAddress to the host computers current IP (for local use only, use 127.0.0.1)
3. Run zonebuilder.py and add any domains you wish to have access to
3. Run server (Windows: python DNSserver.py, Linux: sudo python3 DNSserver.py)
4. For any computer on the network that wants access the DNS server, set its default DNS server to the IP used in step 2
5. Wait a minute and restart and open browsers
6. Use the browser as usual to access any domains that were added to the zones folder
7. If you add any more .zone files, restart the DNS server to update

Bugs: zonebuilder.py does NOT check to see if you entered a valid IP. Invalid IPs, such as 256.255.255.255, can cause the DNS server to crash!