import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("localhost", 8888))
s.listen(1)

(client, address) = s.accept()

state = 0
response = ""

while 1:
  cmd = client.recv(1024).decode("utf-8").strip()

  if cmd == "":
    break

  if cmd == "RESET":
    state = 0
    response = "DONE"
  elif cmd == "A":
    if state == 0:
      response = "C"
    else:
      response = "D"
  elif cmd == "B":
    state = 1 - state
    response = "E"

  client.sendall((response + "\n").encode())
