#!/usr/bin/python

import os
import shutil

import chipwhisperer.capture.ui.CWCaptureGUI as cwc       # Import the ChipWhispererCapture GUI
from chipwhisperer.common.api.CWCoreAPI import CWCoreAPI  # Import the ChipWhisperer API4
from chipwhisperer.common.scripts.base import UserScriptBase
from chipwhisperer.common.utils.parameter import Parameter

class UserScript(UserScriptBase):
    _name = "Benzinegate VCC glitch"

    def __init__(self, api):
        super(UserScript, self).__init__(api)
        self.pname = "benzinegate_vcc_glitch"

    def run(self):
        # Delete previous project files
        if os.path.isfile("projects/%s.cwp" % self.pname): os.remove("projects/%s.cwp" % self.pname)
        #shutil.rmtree("projects/%s_data" % self.pname, ignore_errors=True)

        # Save current open project (default) to a new place
        self.api.saveProject("projects/%s.cwp" % self.pname)

        self.api.setParameter(['Generic Settings', 'Scope Module', 'ChipWhisperer/OpenADC'])
        self.api.setParameter(['Generic Settings', 'Target Module', 'BenzineGate'])
        self.api.setParameter(['Generic Settings', 'Trace Format', 'None'])
        self.api.setParameter(['BenzineGate', 'Crash', True])
        self.api.connect()

        clkgen_freq = 64000000
        lstexample = [
            ['Glitch Module', 'Clock Source', 'CLKGEN'],
            ['OpenADC', 'Clock Setup', 'CLKGEN Settings', 'Desired Frequency', clkgen_freq],
            ['OpenADC', 'Clock Setup', 'ADC Clock', 'Source', 'CLKGEN x1 via DCM'],
            ['OpenADC', 'Clock Setup', 'ADC Clock', 'Reset ADC DCM', None],
            ['OpenADC', 'Clock Setup', 'Freq Counter Src', 'EXTCLK Input'],
            ['CW Extra Settings', 'Trigger Pins', 'Target IO4 (Trigger Line)', False],
            ['CW Extra Settings', 'Target HS IO-Out', 'CLKGEN'],
        ]
        for cmd in lstexample: self.api.setParameter(cmd)

        lstexample = [
            ['OpenADC', 'Gain Setting', 'Mode', 'high'],
            ['OpenADC', 'Gain Setting', 'Setting', 35],
            ['OpenADC', 'Trigger Setup', 'Timeout (secs)', 4.0],
            ['OpenADC', 'Trigger Setup', 'Offset', 0],
            ['OpenADC', 'Trigger Setup', 'Pre-Trigger Samples', 0],
            ['OpenADC', 'Trigger Setup', 'Total Samples', 256],
            ['OpenADC', 'Trigger Setup', 'Mode', 'rising edge'],
        ]
        for cmd in lstexample: self.api.setParameter(cmd)

        lstexample = [
            ['CW Extra Settings', 'Trigger Pins', 'Target IO3 (SmartCard Serial)', True],
            ['CW Extra Settings', 'Trigger Pins', 'Target IO4 (Trigger Line)', True],
            ['CW Extra Settings', 'Trigger Pins', 'Collection Mode', 'AND'],
        ]
        for cmd in lstexample: self.api.setParameter(cmd)

        # ext_offset =  ( 52 * clkgen_freq ) / 32000000 # 2.063 us ~= 66 * 32MHz clocks. 26 seems to line up well
        ext_offset =  ( 140 * clkgen_freq ) / 64000000 # tuned visually between the crash/not-crash paths: 140 samples @ 64MHz

        #compensate for some biases
        if clkgen_freq == 64000000:
            ext_offset -= 12
        elif clkgen_freq == 16000000:
            ext_offset -= 5

        print "Manual Glitch Trigger"
        lstexample = [
            ['Glitch Module', 'Clock Source', 'CLKGEN'],
            #['CW Extra Settings', 'HS-Glitch Out Enable (High Power)', True],
            ['CW Extra Settings', 'HS-Glitch Out Enable (Low Power)', True],
            ['Glitch Module', 'Glitch Width (as % of period)', 9.5],
            ['Glitch Module', 'Glitch Offset (as % of period)', -4],
            ['Glitch Module', 'Glitch Trigger', 'Ext Trigger:Single-Shot'],
            ['Glitch Module', 'Single-Shot Arm', 'After Scope Arm'],
            ['Glitch Module', 'Ext Trigger Offset', ext_offset - 2],
            ['Glitch Module', 'Repeat', 4],
            ['Glitch Module', 'Output Mode', 'Glitch Only'],
        ]
        for cmd in lstexample: self.api.setParameter(cmd)

        #first capture is garbage
        self.api.capture1()

        self.api.setParameter(['Glitch Explorer', 'Normal Response', u"s == ' \\nRegulator status: [XXXXXXXX]\\n'"])
        self.api.setParameter(['Glitch Explorer', 'Successful Response', u"'Your flag:' in s"])

        self.api.setParameter(['Glitch Explorer', 'Plot Widget', None])  # Push the button
        lstexample = [
            ['Glitch Explorer', 'Tuning Parameters', 2],
            ['Glitch Explorer', 'Tuning Parameter 0', 'Name', u'Offset'],
            ['Glitch Explorer', 'Tuning Parameter 0', 'Parameter Path', u"['Glitch Module', 'Glitch Offset (as % of period)']"],
            ['Glitch Explorer', 'Tuning Parameter 0', 'Data Format', 'Float'],
            ['Glitch Explorer', 'Tuning Parameter 0', 'Range', (-30, 30)],
            ['Glitch Explorer', 'Tuning Parameter 0', 'Value', -30.0],
            ['Glitch Explorer', 'Tuning Parameter 0', 'Step', 0.5],
            ['Glitch Explorer', 'Tuning Parameter 0', 'Repeat', 1],

            ['Glitch Explorer', 'Tuning Parameter 1', 'Name', u'Width'],
            ['Glitch Explorer', 'Tuning Parameter 1', 'Parameter Path', u"['Glitch Module', 'Glitch Width (as % of period)']"],
            ['Glitch Explorer', 'Tuning Parameter 1', 'Data Format', 'Float'],
            ['Glitch Explorer', 'Tuning Parameter 1', 'Range', (3, 15)],
            ['Glitch Explorer', 'Tuning Parameter 1', 'Value', 3.0],
            ['Glitch Explorer', 'Tuning Parameter 1', 'Step', 0.5],
            ['Glitch Explorer', 'Tuning Parameter 1', 'Repeat', 1],
            ['Glitch Module', 'Repeat', 1],
            ['Glitch Module', 'Glitch Width (as % of period)', 8.0],
            ['Glitch Explorer', 'Traces Required', 'Use this value', None], # Press "use this value"             
        ]
        for cmd in lstexample: self.api.setParameter(cmd)

if __name__ == '__main__':
    app = cwc.makeApplication()                     # Comment this line if you don't want to use the GUI
    Parameter.usePyQtGraph = True                   # Comment this line if you don't want to use the GUI
    api = CWCoreAPI()                               # Instantiate the API
    gui = cwc.CWCaptureGUI(api)                     # Comment this line if you don't want to use the GUI
    gui.glitchMonitor.show()
    gui.serialTerminal.show()
    api.runScriptClass(UserScript)                  # Run the User Script
    app.exec_()

