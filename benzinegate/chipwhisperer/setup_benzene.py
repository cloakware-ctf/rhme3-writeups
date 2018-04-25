"""Setup script for CWLite with Benzinegate challenge on RHME3

Configures scope settings to prepare for glitch exploration
"""

import numpy

# GUI compatibility
try:
    scope = self.scope
    target = self.target
except NameError:
    pass

scope.glitch.clk_src = 'clkgen'

scope.gain.gain = 40
scope.gain.mode = 'high'

scope.adc.samples = 24400
scope.adc.offset = 0
scope.adc.presamples = 12200
scope.adc.basic_mode = "rising_edge"
scope.adc.timeout = 4.0

scope.clock.clkgen_src = 'system'
scope.clock.clkgen_freq = 16000000 # 64M
scope.clock.adc_src = "clkgen_x4"

scope.trigger.triggers = "tio3 AND tio4"

scope.io.glitch_hp = 0
scope.io.glitch_lp = 1

#also set by BenzineGate target
#scope.io.tio1 = 'serial_tx'
#scope.io.tio2 = 'serial_rx'
#scope.io.tio3 = 'gpio_low'
#scope.io.tio4 = 'high_z'
#scope.io.pdic = 'high'

scope.glitch.clk_src = 'clkgen'
scope.glitch.trigger_src = 'ext_single'
scope.glitch.arm_timing = 'after_scope'
scope.glitch.ext_offset =  ( 124 * scope.clock.clkgen_freq ) / 32000000 # 2.063 us ~= 124 * 32MHz clocks
scope.glitch.repeat = 1
scope.glitch.output = 'glitch_only'

scope.glitch.offset = 0.390625
scope.glitch.width = 40.0 #visual inspection

class IterateGlitchWidthOffset(object):
    MIN_STEP = 0.390625

    def __init__(self, ge_window):
        self.ge_window = ge_window
        self.search = list()
        for offset in numpy.linspace(40.0, -40.0, 10):
            for width in numpy.linspace(40, self.MIN_STEP, 10):
                #TODO search repeat too
                #for repeat in range(1, 3, 1):
                    self.search.append([offset, width])
        self.search_index = 0

    def reset_glitch_to_default(self, scope, target, project):
        self.search_index = 0

    def change_glitch_parameters(self, scope, target, project):
        offset, width = self.search[self.search_index]
        self.search_index =+ 1

        # Write data to scope
        scope.glitch.width = width
        scope.glitch.offset = offset

        #You MUST tell the glitch explorer about the updated settings
        if self.ge_window:
            self.ge_window.add_data("Glitch Width", scope.glitch.width)
            self.ge_window.add_data("Glitch Offset",scope.glitch.offset)

glitch_iterator = IterateGlitchWidthOffset(self.glitch_explorer)
self.aux_list.register(glitch_iterator.change_glitch_parameters, "before_trace")
self.aux_list.register(glitch_iterator.reset_glitch_to_default, "before_capture")

self.api.setParameter(['Glitch Explorer', 'Normal Response', u"s == ' \\nRegulator status: [XXXXXXXX]\\n'"])
self.api.setParameter(['Glitch Explorer', 'Successful Response', u"'Your flag:' in s"])

self.api.setParameter(['Generic Settings', 'Project Settings', 'Trace Format', 'None'])
self.api.setParameter(['Generic Settings', 'Acquisition Settings', 'Number of Traces', len(glitch_iterator.search)])
