VAW Router
==========

V.A.W. stand for VNC AnyWhere in the World, this is a reverse proxy router for VNC.

#How VAW works:
1) Client user, run VAW-Client, give ID and password (showed after it was successfully connected)
to the manager(ie.:by phone), manager connect to VAW router enter the client given ID and password in the interface and he should now be able to remote control the VNC of the client user behind a NAT/firewall

#How to run

##1st generate a SSL certificate:
    openssl req -new -x509 -days 365 -nodes -out self.pem -keyout self.pem

##2nd rune var-router:

    ./vaw-router 4443 --web ../noVNC/

#Status
Early alpha project


