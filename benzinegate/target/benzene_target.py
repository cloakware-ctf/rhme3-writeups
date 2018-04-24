import binascii
from _base import TargetTemplate
from chipwhisperer.common.utils import pluginmanager
from simpleserial_readers.cwlite import SimpleSerial_ChipWhispererLite
import socket
import bitstring
from time import sleep
import logging
import time
from chipwhisperer.common.utils.timer import nonBlockingDelay
from chipwhisperer.common.api.CWCoreAPI import CWCoreAPI
from chipwhisperer.common.utils.parameter import setupSetParam
from chipwhisperer.common.utils import util
import chipwhisperer as cw

class BenzeneGateTarget(TargetTemplate, util.DisableNewAttr):
    _name = 'BenzineGate'

    def __init__(self):
        TargetTemplate.__init__(self)

        ser_cons = pluginmanager.getPluginsInDictFromPackage("chipwhisperer.capture.targets.simpleserial_readers", True, False)
        self.ser = ser_cons[SimpleSerial_ChipWhispererLite._name]
        self.ser.setBaud(115200)

        self._pin = "tio3"
        self._default_state = True
        self._active_ms = 10
        self._delay_ms = 0
        return

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
        return 0

    def loadInput(self, inputtext):
        return

    def readOutput(self):
        return ''

    def isDone(self):
        return True

    def hardware_read(self, num, timeout=100):
        return self.ser.read(num)

    def close(self):
        if self.ser is not None:
            self.ser.close()
            self.ser = None

    @setupSetParam("Connection")
    def setConnection(self, con):
        self.ser = con
        self.params.append(self.ser.getParams())

        self.ser.connectStatus.setValue(False)
        self.ser.connectStatus.connect(self.connectStatus.emit)
        self.ser.selectionChanged()

    def _con(self, scope = None):
        if not scope or not hasattr(scope, "qtadc"): Warning("You need a scope with OpenADC connected to use this Target")

        self.outstanding_ack = False

        self.ser.con(scope)
        return

    def read_line(self):
        res = ''
        char = self.ser.read(1)
        while char != '\n':
            res = res + char
            char = self.ser.read(1)

        return res

    def go(self):
        self.release_and_wait()
        self.ser.write("0123456789abcd" + "stuvwxyz" + binascii.unhexlify("3ffa0002ba") + '\n')
        rx = self.read_line()
        print(rx)
        return

    def release_and_wait(self):
        scope = cw.scope()

        self.setPin(scope, self._pin, not self._default_state)
        nonBlockingDelay(self._active_ms)
        self.setPin(scope, self._pin, self._default_state)
        print(self.read_line())
        print(self.read_line())
        return

    def setPin(self, scope, pin, state):
        """Call like self.setPin(scope, "tio1", True)"""
        setattr(scope.io, pin, state)

