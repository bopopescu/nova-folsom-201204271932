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
Tests for baremetal connection
"""

""" start add by NTT DOCOMO """

import mox

from nova.virt.baremetal.bmdb.sqlalchemy import baremetal_models
from nova import flags
from nova import log as logging
from nova import test

from nova.virt.phy import connection as c


LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS

class FakeVifDriver(object):
    pass

class FakeFirewallDriver(object):
    pass

class FakeVolumeDriver(object):
    pass

def class_path(class_):
    return class_.__module__ + '.' + class_.__name__

class BaremetalConnectionTestCase(test.TestCase):

    def setUp(self):
        super(BaremetalConnectionTestCase, self).setUp()

    def tearDown(self):
        super(BaremetalConnectionTestCase, self).tearDown()

    def _phy_host(self, **kwargs):
        h = baremetal_models.PhyHost()
        h.id = kwargs.get('id', None)
        h.service_id = kwargs.get('service_id', None)
        h.instance_id = kwargs.get('instance_id', None)
        h.cpus = kwargs.get('cpus', 1)
        h.memory_mb = kwargs.get('memory_mb', 1024)
        h.local_gb = kwargs.get('local_gb', 64)
        h.ipmi_address = kwargs.get('ipmi_address', '192.168.1.1')
        h.ipmi_user = kwargs.get('ipmi_user', 'ipmi_user')
        h.ipmi_password = kwargs.get('ipmi_password', 'ipmi_password')
        h.pxe_mac_address = kwargs.get('pxe_mac_address', '12:34:56:78:90:ab')
        h.registration_status = kwargs.get('registration_status', 'done')
        h.task_state = kwargs.get('task_state', None)
        h.pxe_vlan_id = kwargs.get('pxe_vlan_id', None)
        h.terminal_port = kwargs.get('terminal_port', 8000)
        return h
    
    def test_loading_baremetal_drivers(self):
        from nova.virt.baremetal import fake
        self.flags(
                baremetal_driver='fake',
                physical_vif_driver=class_path(FakeVifDriver),
                baremetal_firewall_driver=class_path(FakeFirewallDriver),
                baremetal_volume_driver=class_path(FakeVolumeDriver),
                )
        drv = c.Connection()
        self.assertTrue(isinstance(drv.baremetal_nodes, fake.BareMetalNodes))
        self.assertTrue(isinstance(drv._vif_driver, FakeVifDriver))
        self.assertTrue(isinstance(drv._firewall_driver, FakeFirewallDriver))
        self.assertTrue(isinstance(drv._volume_driver, FakeVolumeDriver))

    def test_find_suitable_phy_host_verify(self):
        h1 = self._phy_host(id=1, memory_mb=512)
        h2 = self._phy_host(id=2, memory_mb=2048)
        h3 = self._phy_host(id=3, memory_mb=1024)
        hosts = [ h1, h2, h3 ]
        inst = {}
        inst['vcpus'] = 1
        inst['memory_mb'] = 1024

        self.mox.StubOutWithMock(c, '_get_phy_hosts')
        c._get_phy_hosts("context").AndReturn(hosts)
        self.mox.ReplayAll()
        result = c._find_suitable_phy_host("context", inst)
        self.mox.VerifyAll()
        self.assertEqual(result['id'], 3)

    def test_find_suitable_phy_host_about_memory(self):
        h1 = self._phy_host(id=1, memory_mb=512)
        h2 = self._phy_host(id=2, memory_mb=2048)
        h3 = self._phy_host(id=3, memory_mb=1024)
        hosts = [ h1, h2, h3 ]
        self.stubs.Set(c, '_get_phy_hosts', lambda self: hosts)
        inst = { 'vcpus': 1 }

        inst['memory_mb'] = 1
        result = c._find_suitable_phy_host("context", inst)
        self.assertEqual(result['id'], 1)

        inst['memory_mb'] = 512
        result = c._find_suitable_phy_host("context", inst)
        self.assertEqual(result['id'], 1)

        inst['memory_mb'] = 513
        result = c._find_suitable_phy_host("context", inst)
        self.assertEqual(result['id'], 3)

        inst['memory_mb'] = 1024
        result = c._find_suitable_phy_host("context", inst)
        self.assertEqual(result['id'], 3)

        inst['memory_mb'] = 1025
        result = c._find_suitable_phy_host("context", inst)
        self.assertEqual(result['id'], 2)

        inst['memory_mb'] = 2048
        result = c._find_suitable_phy_host("context", inst)
        self.assertEqual(result['id'], 2)

        inst['memory_mb'] = 2049
        result = c._find_suitable_phy_host("context", inst)
        self.assertTrue(result is None)

    def test_find_suitable_phy_host_about_cpu(self):
        h1 = self._phy_host(id=1, cpus=1, memory_mb=512)
        h2 = self._phy_host(id=2, cpus=2, memory_mb=512)
        h3 = self._phy_host(id=3, cpus=3, memory_mb=512)
        hosts = [ h1, h2, h3 ]
        self.stubs.Set(c, '_get_phy_hosts', lambda self: hosts)
        inst = { 'memory_mb': 512 }

        inst['vcpus'] = 1
        result = c._find_suitable_phy_host("context", inst)
        self.assertEqual(result['id'], 1)

        inst['vcpus'] = 2
        result = c._find_suitable_phy_host("context", inst)
        self.assertEqual(result['id'], 2)

        inst['vcpus'] = 3
        result = c._find_suitable_phy_host("context", inst)
        self.assertEqual(result['id'], 3)

        inst['vcpus'] = 4
        result = c._find_suitable_phy_host("context", inst)
        self.assertTrue(result is None)

""" end add by NTT DOCOMO """
