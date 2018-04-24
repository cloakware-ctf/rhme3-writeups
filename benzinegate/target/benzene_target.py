from chipwhisperer.capture.targets._base import TargetTemplate
from simpleserial_readers.cwlite import SimpleSerial_ChipWhispererLite
from ._base import SimpleSerialTemplate
import socket
import bitstring
from time import sleep

class BenzeneGateTarget(SimpleSerialTemplate):
    _name = 'BenzeneGate'

    def __init__(self):
        SimpleSerialTemplate.__init__(self)
        self.ser = None
        self.params.addChildren([
            {'name':'Baud', 'key':'baud', 'type':'list', 'values':{'38400':38400, '19200':19200}, 'value':38400},
            {'name':'Port', 'key':'port', 'type':'list', 'values':['Hit Refresh'], 'value':'Hit Refresh'},
            {'name':'Refresh', 'type':'action', 'action':self.updateSerial}
        ])

    def updateSerial(self, _=None):
        serialnames = serialport.scan()
        self.findParam('port').setLimits(serialnames)
        if len(serialnames) > 0:
            self.findParam('port').setValue(serialnames[0])

    def getConnection(self):
        return None

    def setConnection(self, con):
        return

    def init(self):
        pass

    def setModeEncrypt(self):
        return

    def setModeDecrypt(self):
        return

    def loadEncryptionKey(self, key):
        pass

    def textLen(self):
        return 

    def loadInput(self, inputtext):
        return

    def readOutput(self):
        return self.output

    def isDone(self):
        return True

    def hardware_write(self, string):
        return self.ser.write(bytearray(string.encode('utf-8')))

    def hardware_read(self, num, timeout=100):
        return self.ser.read(num)

    def close(self):
        if self.ser is not None:
            self.ser.close()
            self.ser = None

    def con(self, scope = None):
        if self.ser == None:
            # Open serial port if not already
            self.ser = serial.Serial()
            self.ser.port     = self.findParam('port').getValue()
            self.ser.baudrate = self.findParam('baud').getValue()
            self.ser.timeout  = 2     # 2 second timeout
            self.ser.open()

    def go(self):
        self.hardware_write("0123456789abcd"+"stuvwxyz" + "\x3f\xfa\x00\x02\xba")
        #tx = "%s\n" % bitstring.BitString(self.input).hex

        #self.conn.send(tx.encode('utf-8'))
        #rx=self.conn.recv()
        rx = self.hardware_read(43)
        print(rx)
        return