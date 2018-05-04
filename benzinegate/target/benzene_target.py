import binascii
from _base import TargetTemplate
from chipwhisperer.common.utils import pluginmanager
from simpleserial_readers.cwlite import SimpleSerial_ChipWhispererLite
from time import sleep
from chipwhisperer.common.utils import timer
import logging
import time
from chipwhisperer.common.api.CWCoreAPI import CWCoreAPI
from chipwhisperer.common.utils.parameter import setupSetParam
from chipwhisperer.common.utils import util
import chipwhisperer as cw

class BenzineGateTarget(TargetTemplate):
    _name = 'BenzineGate'

    def __init__(self):
        TargetTemplate.__init__(self)

        ser_cons = pluginmanager.getPluginsInDictFromPackage("chipwhisperer.capture.targets.simpleserial_readers", True, False)
        self.ser = ser_cons[SimpleSerial_ChipWhispererLite._name]

        self._active_ms = 10
        self._delay_ms = 0

        self.params.addChildren([
            {'name':'Crash', 'type':'bool', 'key':'crash', 'default':True, 'get':self.getCrash, 'set':self.setCrash, 'psync': True}
            ])

        self._crash = True
        return

    def getCrash(self):
        return self._crash

    @setupSetParam("Crash")
    def setCrash(self, val):
        self._crash = val
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
        self.newInputData.emit(self.output)
        return None

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
        self.cwe = scope.advancedSettings.cwEXTRA

        self.cwe.setTargetIOMode(self.cwe.IOROUTE_STX, 0)
        self.cwe.setTargetIOMode(self.cwe.IOROUTE_SRX, 1)
        self.cwe.setTargetIOMode(self.cwe.IOROUTE_GPIOE, 2)
        self.cwe.setGPIOState(False, 2)
        self.cwe.setTargetIOMode(self.cwe.IOROUTE_HIGHZ, 3)
        self.cwe.setGPIOState(True, 102)

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


        self.cwe.setGPIOState(True, 2)
        if self._crash:
            self.ser.write("0123456789abcd" + "stuvwxyz" + binascii.unhexlify("3ffa0002ba") + '\n')
        else:
            self.ser.write("01234" + '\n')

        then = time.time()
        while time.time() - then < 0.100:
            self.output.extend(self.ser.read(1).encode('utf-8'))
        self.cwe.setGPIOState(False, 2)

        print(self.output)
        return

    def nonblockingSleep_done(self):
        self._sleeping = False

    def nonBlockingSleep(self, stime):
        """Sleep for given number of seconds (~50mS resolution), but don't block GUI while we do it"""
        timer.Timer().singleShot(stime * 1000, self.nonblockingSleep_done)
        self._sleeping = True
        while(self._sleeping):
            time.sleep(0.01)
            util.updateUI()

    def release_and_wait(self):
        self.cwe.setGPIOState(False, 102)
        self.nonBlockingSleep(self._active_ms)
        self.cwe.setGPIOState(True, 102)
        self.read_until('>')
        return

