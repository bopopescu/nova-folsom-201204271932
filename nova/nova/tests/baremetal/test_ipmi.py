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
Tests for baremetal impi driver
"""

""" start add by NTT DOCOMO """

import mox

import os
import stat

from nova import flags
from nova import log as logging
from nova import test
from nova import utils

from nova.virt.phy import ipmi

LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS

class BaremetalIPMITestCase(test.TestCase):

    def setUp(self):
        super(BaremetalIPMITestCase, self).setUp()

    def tearDown(self):
        super(BaremetalIPMITestCase, self).tearDown()
    
    def test_make_password_file(self):
        PASSWORD = 'xyz'
        path = ipmi._make_password_file(PASSWORD)
        self.assertTrue(os.path.isfile(path))
        self.assertEqual(os.stat(path)[stat.ST_MODE] & 0777, 0600)
        try:
            with open(path, "r") as f:
                s = f.read(100)
            self.assertEqual(s, PASSWORD)
        finally:
            os.unlink(path)
    
    def test_exec_ipmitool(self):
        H = 'address'
        U = 'user'
        P = 'password'
        I = 'interface'
        F = 'password_file'
        
        self.mox.StubOutWithMock(ipmi, '_make_password_file')
        self.mox.StubOutWithMock(utils, 'execute')
        self.mox.StubOutWithMock(ipmi, '_unlink_without_raise')
        ipmi._make_password_file(P).AndReturn(F)
        args = [
                'ipmitool',
                '-I', I,
                '-H', H,
                '-U', U,
                '-f', F,
                'A', 'B', 'C',
                ]
        utils.execute(*args, attempts=3).AndReturn(('', ''))
        ipmi._unlink_without_raise(F).AndReturn(None)
        self.mox.ReplayAll()

        i = ipmi.Ipmi(address=H, user=U, password=P, interface=I)
        i._exec_ipmitool('A B C')
        self.mox.VerifyAll()


""" end add by NTT DOCOMO """
