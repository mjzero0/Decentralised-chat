# Decentralised-chat


pip install websockets

1  edit chat within 1 server

2  implement, introducer part

3  implement more than 1 server, related to 2


in the server.py INTRODUCER_HOST should be the IP address of the device that is hosting the introducer
MY_HOST line 26, the IP address should be the IP address of the server device


the client.py SERVER_HOST line 19, the IP address should be the one's you want to connect to, it could be your own device or the device that is running the server AND you want to connect to


in order to send file, you need to use the command /file <username> <file name>, that works only if the file is within the current working folder.
if you want to send a file from another location on your computer, you need to use this command: /file <username> /filelocation/filename
NOTE: <username> refers to the username which you want to send files to