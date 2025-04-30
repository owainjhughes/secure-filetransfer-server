## Secure client-server file transfer system

# Usage
Server: java Server.java 5678
Client: java Client.java localhost 5678 <user>
Testing has been done only with user alice; any other user would result in error as only 'alice' and 'server' keys were in working directory

Client commands are ls, get <filename>, bye
