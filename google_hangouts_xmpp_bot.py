#!/usr/bin/env python2.7
# -- coding: utf-8 -

import xmpp
import pyotp
import requests

user="username@domain.com"
password="app_password"
server=('talk.google.com', 5223)


def message_handler(connect_object, message_node):
    received_text=str(message_node.getBody())
    if received_text <> 'None':
        print "Received Message {0}".format(received_text)
        connect_object.send(xmpp.Message( message_node.getFrom() , "Got your message!", typ='chat' ))


jid = xmpp.JID(user)
connection = xmpp.Client(jid.getDomain())
connection.connect(server)
result = connection.auth(jid.getNode(), password )

connection.RegisterHandler('message', message_handler)
connection.sendInitPresence()

while connection.Process(1):
    pass
