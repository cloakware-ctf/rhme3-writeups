# This script bridges two CAN interfaces, so that anything received on one is
# sent on the other, and vice-versa.

from __future__ import print_function
import sys
import can
import time

Bus0 = can.interface.Bus(bustype='socketcan', channel='can0', bitrate=49500)
Bus1 = can.interface.Bus(bustype='socketcan', channel='can1', bitrate=49500)

Tracker = False

def modify(msg):
    print(msg)
    return msg

def bridge():
    delay = 0.001
    while True:
        start = time.time()

        msg = Bus0.recv(0)
        if msg != None:
            sys.stdout.write("\ncan0: ")
            msg = modify(msg)
            if msg != None:
                Bus1.send(msg)
                if Tracker: sys.stdout.write('*')
            else:
                if Tracker: sys.stdout.write('x')

        msg = Bus1.recv(0)
        if msg != None:
            sys.stdout.write('can1: ')
            msg = modify(msg)
            if msg != None:
                Bus0.send(msg)
                if Tracker: sys.stdout.write('-')
            else:
                if Tracker: sys.stdout.write('_')

        delta = time.time() - start
        if (delta < delay):
            time.sleep(delay - delta)

if __name__ == "__main__":
    # recv_loop()
    # saturate_loop()
    print("starting:")
    bridge()

