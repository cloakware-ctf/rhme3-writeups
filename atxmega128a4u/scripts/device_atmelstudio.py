'''
            GDP - The Generic Device Programmer.

    By Dean Camera (dean [at] fourwalledcubicle [dot] com)

   Release under a MIT license; see LICENSE.txt for details.
'''

import os.path
import xml.etree.ElementTree as ET

from devices import *


class DeviceAtmelStudio(Device):
    def __init__(self, part=None):
        if part is None:
            raise DeviceError("Device part name must be specified.")

        device_filenames = {
            "devicefiles/%s.atdf" % part,
            "devicefiles/%s.xml" % part
        }

        part_filename = ""
        for filename in device_filenames:
            if os.path.isfile(filename):
                part_filename = filename
                break

        try:
            self.device_tree = ET.parse(part_filename)
        except IOError:
            raise DeviceError("Could not open the specified part file.")

        self.device_info = self.device_tree.find("devices/device[1]")


    @staticmethod
    def _param_to_int(param_info):
        param_values = []

        for p in param_info.split():
            if p.startswith("0x"):
                param_values.append(int(p, 16))
            else:
                param_values.append(int(p, 10))

        return param_values[0] if len(param_values) == 1 else param_values


    def get_name(self):
        return self.device_info.get("name").lower()


    def get_family(self):
        return self.device_info.get("family").lower()


    def get_architecture(self):
        return self.device_info.get("architecture").lower()


    def get_vcc_range(self):
        dev_variant = self.device_tree.find("variants/variant[1]")
        return (float(dev_variant.get("vccmin")),
                float(dev_variant.get("vccmax")))


    def get_supported_interfaces(self):
        dev_interfaces = self.device_info.findall("interfaces/interface")
        return [i.get("name").lower() for i in dev_interfaces]


    def get_property(self, group, param):
        param_group = self.device_info.find("property-groups/property-group[@name='%s']" % group.upper())
        if param_group is None:
            raise DeviceMissingInfoError("property group", group)

        param_info = param_group.find("property[@name='%s']" % param)
        if param_info is None:
            raise DeviceMissingInfoError("group \"%s\" parameter" % group, param)

        return self._param_to_int(param_info.get("value"))


    def get_signature(self, interface):
        if interface == "jtag":
            return self.get_property("signatures", "JTAGID")
        else:
            dev_signature = []

            try:
                while True:
                    dev_signature.append(self.get_property("signatures", "SIGNATURE%d" % len(dev_signature)))
            finally:
                return dev_signature


    def get_section_bounds(self, memory_type=None, segment_name=None):
        mem_segments = self.device_info.findall("address-spaces/address-space/memory-segment")
        if mem_segments is None:
            raise DeviceMissingInfoError("memory segment", memory_type)

        segment_info = []

        for segment in mem_segments:
            if not memory_type is None:
                if not segment.get("type").lower() == memory_type:
                    continue

            if not segment_name is None:
                if not segment.get("name").lower() == segment_name:
                    continue

            seg_start = self._param_to_int(segment.get("start"))
            seg_end   = seg_start + self._param_to_int(segment.get("size"))

            segment_info.append((seg_start, seg_end))

        return segment_info


    def get_page_size(self, memory_type):
        mem_segment = self.device_info.find("address-spaces/address-space/memory-segment[@type='%s']" % memory_type.lower())
        if mem_segment is None:
            raise DeviceMissingInfoError("memory segment", memory_type)

        page_size_value = mem_segment.get("pagesize")
        if page_size_value is None:
            return 1

        return self._param_to_int(page_size_value)
