from __future__ import print_function
import sys
import can
import time

Bus0 = can.interface.Bus(bustype='socketcan', channel='can0', bitrate=49500)

def saturateLoop():
    Counter = 0
    #for aid in [0x7e5, 0x7e8, 0x7ed, 0x7db, 0x7df]:
    #for aid in range(0, 0x800):
    for aid in [0x7e0]:
        print("Fuzzing AID: 0x%03X#"%(aid))
        for sysId in range(0x12, 0x40):
            for subId in range(0,1):
                msg = can.Message(arbitration_id=aid,
                          data=[0x02, sysId, subId, 0,0,0,0,0],
                          extended_id=False)
                Bus0.send(msg)
                time.sleep(0.5)
                flushPrint()

SeenErrors = []
def flushPrint():
    global SeenErrors
    dataLen = 0
    data = ""
    inProgress = False
    while(True):
        msg = Bus0.recv(0)
        if (msg==None):
            return
        aid = msg.arbitration_id
        frame = msg.data[0]>>4

        if (frame==0 and msg.data[1]==0x7f): # error frame
            length = msg.data[0] & 0xf
            error = msg.data[0:4]
            if (error) in SeenErrors and length==3:
                continue
            SeenErrors.append(error)
            sysid = msg.data[1]
            subid = msg.data[2]
            code = msg.data[3]
            print("%03x:[%02x:%02x] %02x Error"%(aid, sysid, subid, code))

        elif (frame==0):
            # if (inProgress): continue
            length = msg.data[0] & 0xf
            sysid = msg.data[1] & 0x3f
            subid = msg.data[2]
            if ignore(aid, sysid, subid):
                continue
            if ((msg.data[1] & 0x40)==0x40):
                resp = '<'
            else:
                resp = '>'
            sys.stdout.write("%03x:[%02x:%02x] %c "%(aid, sysid, subid, resp))
            for c in msg.data[3:length+1]:
                sys.stdout.write("%02x"%(c))
            sys.stdout.write("  ")
            for c in msg.data[3:length+1]:
                sys.stdout.write("%c"%(c))
            sys.stdout.write("\n")

        elif (frame==1):
            dataLen = (msg.data[0] & 0xf)*256 + msg.data[1]
            sysid = msg.data[2] & 0x3f
            subid = msg.data[3]
            if ignore(aid, sysid, subid):
                continue
            if ((msg.data[2] & 0x40)==0x40):
                resp = '<'
            else:
                resp = '>'
            sys.stdout.write("%03x:[%02x:%02x] %c "%(aid, sysid, subid, resp))
            length = min(8, dataLen)
            for c in msg.data[4:length+1]:
                sys.stdout.write("%02x"%(c))
            for c in msg.data[4:length+1]:
                data += chr(c)
            dataLen -= (length - 4)
            inProgress = True

        elif (frame==2):
            # TODO: de-interleave
            if (not inProgress):
                continue
            length = min(8, dataLen+1)
            for c in msg.data[1:length+1]:
                sys.stdout.write("%02x"%(c))
            for c in msg.data[1:length+1]:
                data += chr(c)
            dataLen -= (length - 1)
            if (dataLen<=3):
                print(" ",data)
                inProgress = False

ignoreList = [
    [0x7E5, 0x09, 0x00],
    [0x7E5, 0x09, 0x0A],
    [0x7E5, 0x01, 0x00],
    [0x7E5, 0x01, 0x0D],
    [0x7DF, 0x01, 0x00],
    [0x7DF, 0x01, 0x20],
    [0x7DF, 0x01, 0x40],
    [0x7DF, 0x01, 0x42],
    [0x7ED, 0x01, 0x00],
    [0x7ED, 0x01, 0x0D],
    [0x7ED, 0x01, 0x20],
    [0x7ED, 0x01, 0x40],
    [0x7ED, 0x01, 0x42],
    [0x7ED, 0x09, 0x00],
    [0x7ED, 0x09, 0x0a]
]
def ignore(aid, sysid, subid):
    for ignore in ignoreList:
        if ignore[0]==aid and ignore[1]==sysid and ignore[2]==subid:
            return True
    return False

if __name__ == "__main__":
    print("ready")
    saturateLoop()


