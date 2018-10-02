#!/usr/bin/python

import socket
import sys
import os
from select import select
import struct

NETLINK_USERSOCK = 2
NETLINK_ADD_MEMBERSHIP = 1
SOL_NETLINK = 270

nlgroup = 24


class NlMsg:
    def __init__(self, data):
        self.Length = 0 # uint32
        self.Type = 0 # uint16
        self.Flags = 0 # uint16
        self.SeqNum = 0 # uint32
        self.PortID = 0 # uint32, PID for first socket of Process. If the message comes from kernel PortID is 0
        self.Payload = "" # raw string
        self.fromWire(data)

    # wire format is host byte order
    def fromWire(self, raw_message):
        # extract nl header
        self.Length, self.Type, self.Flags, self.SeqNum, self.PortID = struct.unpack("@IHHII", raw_message[:16])
        # extract payload
        self.Payload = raw_message[16:self.Length]

    def __str__(self):
        return "Netlink msg: Length %d, Type %d, Flags %d, SeqNum %d, PortID %d, Payload %s" % (self.Length, self.Type, self.Flags, self.SeqNum, self.PortID, repr(self.Payload))


# open socket to receive multicast message from driver
#########################################################
try:
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_USERSOCK)
except socket.error:
    print("Error creating netlink socket for Firmware multicasts")
    sys.exit(-1)

# bind to kernel
s.bind((os.getpid(), 0))

# 270 is SOL_NETLINK and 1 is NETLINK_ADD_MEMBERSHIP
try:
    s.setsockopt(SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, nlgroup)
except socket.error:
    print("Failed to attach to netlink multicast group {0}, try with root permissions".format(nlgroup))
    sys.exit(-1)

print("Waiting for netlink messages of patched dwc2 kernel module on multicast group %d" % (nlgroup))

# read loop
sfd = s.fileno()
while True:
    read_timeout = 0.5
    sel = select([sfd], [], [], read_timeout) # test if readable data arrived on nl_socket, interrupt after timeout
    if len(sel[0]) == 0:
        # no data arrived
        # print "No data"
        continue

    data = s.recvfrom(0xFFFF)[0]
    parsed = NlMsg(data)
    if parsed.Payload == '\x01':
        print("dwc2 gadget connected to USB host")
    else:
        print("dwc2 gadget disconnected from USB host")


# unbind socket
s.close()