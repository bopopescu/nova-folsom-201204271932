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

"""
Tests for baremetal pxe driver
"""

""" start add by NTT DOCOMO """

import mox

from nova import exception
from nova import flags
from nova import log as logging
from nova import test

from nova.virt.phy import pxe

LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS

class BaremetalPXETestCase(test.TestCase):

    def setUp(self):
        super(BaremetalPXETestCase, self).setUp()

    def tearDown(self):
        super(BaremetalPXETestCase, self).tearDown()
    
    def test_init(self):
        self.flags(
                physical_deploy_kernel="x",
                physical_deploy_ramdisk="y",
                )
        pxe.PXE()

        self.flags(
                physical_deploy_kernel=None,
                physical_deploy_ramdisk="y",
                )
        self.assertRaises(exception.NovaException, pxe.PXE)

        self.flags(
                physical_deploy_kernel="x",
                physical_deploy_ramdisk=None,
                )
        self.assertRaises(exception.NovaException, pxe.PXE)


""" end add by NTT DOCOMO """
