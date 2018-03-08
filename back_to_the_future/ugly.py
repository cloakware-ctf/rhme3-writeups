from __future__ import print_function
import sys
import can
import time

Bus0 = can.interface.Bus(bustype='socketcan', channel='can0', bitrate=49500)
Bus1 = can.interface.Bus(bustype='socketcan', channel='can1', bitrate=49500)

msg023 = can.Message(arbitration_id=0x023,
                  data=[0, 88, 2200/256, 2200%256, 0x20],
                  extended_id=False)
msg19a = can.Message(arbitration_id=0x19a,
                  data=[0x71, 0x20],
                  extended_id=False)

msg10c = can.Message(arbitration_id=0x10c,
                  data=[0, 0x4a, 1, 0x20, 0, 0x4a, 0, 0x4a],
                  extended_id=False)
msg1bf = can.Message(arbitration_id=0x1bf,
                  data=[0, 12, 0, 15, 0, 12],
                  extended_id=False)
msg012 = can.Message(arbitration_id=0x012,
                  data=[0x06, 0x21],
                  extended_id=False)

msg202 = can.Message(arbitration_id=0x202,
                  data=[0, 0x4c, 0, 0x4a, 0x52],
                  extended_id=False)

FlipFlop = 0
def init0():
    global FlipFlop
    FlipFlop += 1
    if (FlipFlop%2==0):
        Bus0.send(msg023)
        Bus0.send(msg19a)
        Bus0.send(msg202)
    else:
        Bus0.send(msg023b)
        Bus0.send(msg19ab)
        Bus0.send(msg202b)

def init1():
    Bus1.send(msg10c)
    Bus1.send(msg1bf)
    Bus1.send(msg012)

def saturate_loop():
    Counter = 0
    while True:
        if Counter%100 == 0:
            Bus.send(msg023)
        Counter += 1
        Bus.send(msg19a)
        time.sleep(0.005)

oldRPM = 0
def modify(msg):
    if (msg.arbitration_id == 0x023):
        msg.data[1]=88
        newRPM = msg.data[2]*256 + msg.data[3]
        targetRPM = newRPM + 500
        global oldRPM
        if oldRPM == targetRPM:
            oldRPM += 10
        else:
            oldRPM = targetRPM
        msg.data[2] = oldRPM / 256
        msg.data[3] = oldRPM % 256
    Bus1.send(msg19a)
    return msg

def bridge():
    delay = 0.001
    while True:
        start = time.time()

        msg = Bus0.recv(0)
        if msg != None:
            msg = modify(msg)
            if msg != None:
                Bus1.send(msg)
                sys.stdout.write('*')
            else:
                sys.stdout.write('x')

        msg = Bus1.recv(0)
        if msg != None:
            msg = modify(msg)
            if msg != None:
                Bus0.send(msg)
                sys.stdout.write('-')
            else:
                sys.stdout.write('_')


        delta = time.time() - start
        if (delta < delay):
            time.sleep(delay - delta)

def recv_loop():
    while True:
        r = Bus.recv()
        if (r == None):
            q=1
        elif (r.arbitration_id == 0x023):
            q=1
            #Bus.send(msg023)
        elif (r.arbitration_id == 0x012):
            q=1
            #Bus.send(msg19a)
            #Bus.send(msg202)
        elif (r.arbitration_id == 0x202):
            q=1
            #Bus.send(msg19a)
            #Bus.send(msg10c)
            #Bus.send(msg1bf)
            #Bus.send(msg012)
        else:
            q=1

        if (r == None):
            sys.stdout.write('.')
        elif (r.arbitration_id == 0x023):
            sys.stdout.write('*')
        elif (r.arbitration_id == 0x012):
            sys.stdout.write('x')
        elif (r.arbitration_id == 0x202):
            sys.stdout.write('+')
        else:
            sys.stdout.write('-')

if __name__ == "__main__":
    # recv_loop()
    # saturate_loop()
    print("ready")
    bridge()


