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

class BenzineGateTarget(TargetTemplate, util.DisableNewAttr):
    _name = 'BenzineGate'

    def __init__(self):
        TargetTemplate.__init__(self)

        ser_cons = pluginmanager.getPluginsInDictFromPackage("chipwhisperer.capture.targets.simpleserial_readers", True, False)
        self.ser = ser_cons[SimpleSerial_ChipWhispererLite._name]

        self._active_ms = 10
        self._delay_ms = 0
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
        return self.output

    def isDone(self):
        return True

    def close(self):
        if self.ser is not None:
            self.ser.close()
        return

    @setupSetParam("Connection")
    def setConnection(self, con):
        self.ser = con
        self.params.append(self.ser.getParams())

        self.ser.connectStatus.setValue(False)
        self.ser.connectStatus.connect(self.connectStatus.emit)
        self.ser.selectionChanged()
        return

    def _con(self, scope = None):
        if not scope or not hasattr(scope, "qtadc"):
            Warning("You need a scope with OpenADC connected to use this Target")

        self.ser.con(scope)

        self.ser.findParam('baud').setValue(115200)

        self.scope = scope

        self.scope.io.tio1 = "serial_tx"
        self.scope.io.tio2 = "serial_rx"
        self.scope.io.tio3 = "gpio_low"
        self.scope.io.tio4 = "high_z"
        self.scope.io.pdic = "high"

        return

    def read_line(self):
        res = ''
        char = self.ser.read(1)
        while char != '\n':
            res = res + char
            char = self.ser.read(1)

        return res

    def read_until(self, prompt_char):
        char = self.ser.read(1)
        while char != prompt_char:
            char = self.ser.read(1)
        return

    def go(self):
        self.output = bytearray()
        self.ser.flush()

        self.release_and_wait()


        self.scope.io.tio3 = "gpio_high"
        self.ser.write("0123456789abcd" + "stuvwxyz" + binascii.unhexlify("3ffa0002ba") + '\n')

        then = time.time()
        while time.time() - then < 0.100:
            self.output.extend(self.ser.read(1).encode('utf-8'))
        self.scope.io.tio3 = "gpio_low"

        print(self.output)
        return

    def release_and_wait(self):
        self.scope.io.pdic = "low"
        nonBlockingDelay(self._active_ms)
        self.scope.io.pdic = "high"
        self.read_until('>')
        return

