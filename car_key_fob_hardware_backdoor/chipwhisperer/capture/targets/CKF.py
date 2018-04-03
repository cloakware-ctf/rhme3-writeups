from chipwhisperer.capture.targets._base import TargetTemplate
import socket
import bitstring
from time import sleep

class CKFTarget(TargetTemplate):
    _name = 'Car Keyfob'

    def __init__(self):
        TargetTemplate.__init__(self)

        self.key = ''
        self.keylength=16
        self.textlength=64
        self.outputlength=16
        self.input = ''
        self.output  = ''

    def setKeyLen(self, klen):
        """ Set key length in BITS """
        self.keylength = klen / 8

    def keyLen(self):
        """ Return key length in BYTES """
        return self.keylength

    def getConnection(self):
        return None

    def setConnection(self, con):
        return

    def con(self, scope=None):
        self.conn = socket.socket()
        self.conn.connect(('lu', 32888))

        self.connectStatus.setValue(True)
        return

    def close(self):
        self.conn.close()
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
        return self.textlength

    def loadInput(self, inputtext):
        self.input = inputtext
        return

    def readOutput(self):
        return self.output

    def isDone(self):
        return True

    def checkEncryptionKey(self, kin):
        return kin

    def go(self):
        tx = "%s\n" % bitstring.BitString(self.input).hex

        self.conn.send(tx.encode('utf-8'))
        rx=self.conn.recv(17)
        rx=rx[0:15]

        self.output = bytearray(bitstring.BitString(hex=rx.decode('utf-8')).tobytes())
        sleep(2)
        return

