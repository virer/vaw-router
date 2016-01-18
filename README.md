VAW Router
==========

V.A.W. stand for VNC AnyWhere in the World, this is a reverse proxy router for VNC.

#How VAW works:
1) Client user, run VAW-Client, give ID and password (showed after it was successfully connected)
to the manager(ie.:by phone), manager connect to VAW router enter the client given ID and password in the interface and he should now be able to remote control the VNC of the client user behind a NAT/firewall

#How to run

    ./vaw-router 4443 --web ../noVNC/

Note: You must have generated the SSL certificate to support websocket SSL

#Status
Early alpha project


