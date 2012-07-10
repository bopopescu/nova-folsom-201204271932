# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 NTT DOCOMO, INC. 
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

""" start add by NTT DOCOMO """

from nova import flags
from nova import log as logging


LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS


def get_baremetal_nodes():
    return Fake()


class Fake:

    def __init__(self):
        pass

    def define_vars(self, instance, network_info, block_device_info):
        return {}

    def create_image(self, var, context, image_meta, host, instance):
        pass

    def destroy_images(self, var, context, host, instance):
        pass
    
    def activate_bootloader(self, var, context, host, instance):
        pass

    def deactivate_bootloader(self, var, context, host, instance):
        pass
    
    def activate_node(self, var, context, host, instance):
        """For operations after power on"""
        pass
    
    def deativate_node(self, var, context, host, instance):
        """For operations before power off"""
        pass
    
    def get_console_output(self, host, instance):
        return 'fake\nconsole\noutput for instance %s' % instance['id']

""" end add by NTT DOCOMO """
