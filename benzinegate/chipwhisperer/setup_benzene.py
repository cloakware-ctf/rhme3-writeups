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

scope.gain.gain = 35
scope.gain.mode = 'high'

scope.adc.samples = 256
scope.adc.offset = 0
scope.adc.presamples = 0
scope.adc.basic_mode = "rising_edge"
scope.adc.timeout = 4.0

scope.clock.clkgen_src = 'system'
scope.clock.clkgen_freq = 64000000 # 64M
scope.clock.adc_src = "clkgen_x1"

scope.trigger.triggers = "tio3 AND tio4"

scope.io.hs2       = 'clkgen'

#also set by BenzineGate target
#scope.io.tio1 = 'serial_tx'
#scope.io.tio2 = 'serial_rx'
#scope.io.tio3 = 'gpio_low'
#scope.io.tio4 = 'high_z'
#scope.io.pdic = 'high'

scope.io.glitch_hp = 1
scope.io.glitch_lp = 0
scope.glitch.clk_src = 'clkgen'
scope.glitch.trigger_src = 'ext_single'
scope.glitch.arm_timing = 'after_scope'

# scope.glitch.ext_offset =  ( 52 * scope.clock.clkgen_freq ) / 32000000 # 2.063 us ~= 66 * 32MHz clocks. 26 seems to line up well
scope.glitch.ext_offset =  ( 140 * scope.clock.clkgen_freq ) / 64000000 # tuned visually between the crash/not-crash paths: 140 samples @ 64MHz

#compensate for some biases
if scope.clock.clkgen_freq == 64000000:
    scope.glitch.ext_offset -= 12
elif scope.clock.clkgen_freq == 16000000:
    scope.glitch.ext_offset -= 5

scope.glitch.repeat = 1
scope.glitch.output = 'glitch_only'

scope.glitch.offset = 0.390625
scope.glitch.width = 40.0 #visual inspection

class IterateGlitchWidthOffset(object):
    MIN_STEP = 0.390625
    OFFSET_STEPS = 64
    WIDTH_STEPS = 4

    def __init__(self, ge_window):
        self.ge_window = ge_window
        self.search = list()
        for offset in numpy.append(numpy.linspace(49.0, self.MIN_STEP, self.OFFSET_STEPS/2), numpy.linspace(-1.0 * self.MIN_STEP, -49.0, self.OFFSET_STEPS/2)):
            for width in numpy.linspace(40, 10, self.WIDTH_STEPS):
                for ext_offset in [ scope.glitch.ext_offset, scope.glitch.ext_offset - 1, scope.glitch.ext_offset + 1 ]:
                    #TODO search repeat too
                    #for repeat in range(1, 3, 1):
                        self.search.append([offset, width, ext_offset])
        self.search_index = 0

        self.search = list()
        offset = -40
        while offset <= 40:
            width = 5
            while width <= 40:
                self.search.append([offset, width, scope.glitch.ext_offset])

                width += self.MIN_STEP * 40
            offset += self.MIN_STEP * 20

        print(self.search)

    def reset_glitch_to_default(self, scope, target, project):
        self.search_index = 0

    def change_glitch_parameters(self, scope, target, project):
        offset, width, ext_offset = self.search[self.search_index]
        self.search_index = self.search_index + 1

        # Write data to scope
        scope.glitch.width = width
        scope.glitch.offset = offset
        #scope.glitch.ext_offset = ext_offset

        #You MUST tell the glitch explorer about the updated settings
        if self.ge_window:
            self.ge_window.add_data("Glitch Width %", scope.glitch.width)
            self.ge_window.add_data("Glitch Offset %",scope.glitch.offset)
            self.ge_window.add_data("Delay CLKs", scope.glitch.ext_offset)

glitch_iterator = IterateGlitchWidthOffset(self.glitch_explorer)
self.aux_list.register(glitch_iterator.change_glitch_parameters, "before_trace")
self.aux_list.register(glitch_iterator.reset_glitch_to_default, "before_capture")

self.api.setParameter(['Glitch Explorer', 'Normal Response', u"s == ' \\nRegulator status: [XXXXXXXX]\\n'"])
self.api.setParameter(['Glitch Explorer', 'Successful Response', u"'Your flag:' in s"])

self.api.setParameter(['Generic Settings', 'Project Settings', 'Trace Format', 'None'])
self.api.setParameter(['Generic Settings', 'Acquisition Settings', 'Number of Traces', len(glitch_iterator.search)])
