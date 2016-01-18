VAW Router
==========

V.A.W. stand for VNC AnyWhere in the World, this is a reverse proxy router for VNC.

#How VAW works:
1) Client user, run VAW-Client, give ID and password (showed after it was successfully connected)
to the manager(ie.:by phone), manager connect to VAW router enter the client given ID and password in the interface and he should now be able to remote control the VNC of the client user behind a NAT/firewall

#How to run
use websockify(as it was early websockify is not intergrated for the moment) like this

    ./run 4443 -D 127.0.0.1:1520

Then launch the vaw-router server

    python server.py

Note: You must have generated the SSL certificate to support websocket SSL

#Status
Early alpha project

#Protocol details:

              DATA                                                   WAY (r=vaw router; c=client; m=manager) 
    1   *initial tcp connection                                      r<c!
    2   { "method": "client" }                                       r<c
    3   { "id": <clientID(Int)>, "pw": "<randomString>" }            r>c
        *now client & server wait for manager action
    5   *initial tcp connection                                      r<m!
    6  { "method": "manager", "id": <clientId(int)> }                r<m
    7  { "success": true, "manager_id": <managerId(Int)> }           r>m
    8  { "method": "passwd", "pw": "<clientPasswordHash(sha256)>" }  r<m
    9a { "success": true }                                           r>m
    9b { "vnc": "connect" }                                          r>c

NB: manager can also connect before step 5


                  

