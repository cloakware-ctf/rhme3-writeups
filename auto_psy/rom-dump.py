from __future__ import print_function
import sys
import can
import time

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
        if (msg.arbitration_id != RecvAID):
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
                msg.data = data
                return msg
    # the pigfuckers lie. The last block does not correctly report size!
    if (storedMsg != None and dataLen != 0):
        storedMsg.data = data
        return storedMsg
    else:
        print("Oops:",dataLen,len(data))
        return None

def doubleScan():
    request = can.message(arbitration_id=sendaid,
            data=[0x10, 0x0b, 0x35, 0x00, 0x44, 0x00, 0x00, offset*16],
            extended_id=false)
    print(request)
    bus0.send(request)
    request = can.message(arbitration_id=sendaid,
            data=[0x21, 0x00, 0x00, 0x00, 0x00, 0x01, 0,0],
            extended_id=false)
    print(request)
    bus0.send(request)

def scanRam():
    # Note: hit with f1bc -> f287
    print("Forcing Time!")
    modifier = 0
    errorCount = 0
    for offset in range(0,256):
        request = can.Message(arbitration_id=SendAID,
                data=[0x07, 0x35, 0x00, 0x22, offset,0,0,4],
                extended_id=False)
        print(request)
        Bus0.send(request)
        msg = getReply(RecvAID, 0x35)
        if (msg == None):
            print("no reply")
        elif (msg.data[1] == 0x7f and msg.data[3]==0x31):
            errorCount += 1
        else:
            print(msg)
    if (errorCount > 0):
        print("Errors:",errorCount)

def dumpRam(address, length, filename):
    request = can.Message(arbitration_id=SendAID,
            data=[0x07, 0x35, 0x00, 0x22, address/256,address%256, length/256,length%256],
            extended_id=False)
    print(request)
    Bus0.send(request)
    reply = getReply(RecvAID, 0x35)
    print(reply)
    if (reply == None):
        print("no reply")
        return False
    elif (reply.data[1] == 0x7f):
        print("error")
        return False
    blocks = (length+reply.data[3]-1) / reply.data[3]

    dump = open(filename, "w")
    try:
        for block in range(0,blocks):
            getBlock = can.Message(arbitration_id=SendAID,
                    data=[0x02, 0x36, (block+1)%256, 0,0,0,0,0],
                    extended_id=False)
            Bus0.send(getBlock)
            repBlock = getReply(RecvAID, 0x36)
            print(repBlock)
            if (repBlock == None):
                print("no reply")
                return False
            elif (reply.data[1] == 0x7f):
                print("error")
                return False
            dump.write(repBlock.data[3:]) # first three bytes are length/$PID/block

    finally:
        request = can.Message(arbitration_id=SendAID,
                data=[0x01, 0x37, 0,0,0,0,0,0],
                extended_id=False)
        print(request)
        Bus0.send(request)
        reply = getReply(RecvAID, 0x37)
        print(reply)
        dump.close

if __name__ == "__main__":
    if (len(sys.argv) < 2):
        print("Usage:",sys.argv[0],"<AID>")
        exit(1)
    else:
        SendAID = int(sys.argv[1],0)
        RecvAID = SendAID+8

    print("using aid:",hex(SendAID))
    #scanRam();

    print("WARNING: there is a BUG in this code.")
    print("you may have to re-run multiple times to get good dumps.")
    width = 0x800
    for addr in range(0,0x10000,width):
        dumpRam(addr, width, "mem-dump-%03x-%04x.raw"%(SendAID,addr))

