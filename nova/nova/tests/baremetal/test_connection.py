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
from nova.virt.baremetal import bmdb
from nova.virt.firewall import NoopFirewallDriver

"""
Tests for baremetal connection
"""

""" start add by NTT DOCOMO """

import mox

from nova import flags, db
from nova import log as logging
from nova import test
from nova.tests import utils as test_utils

from nova.virt.phy import driver as c, physical_states
from nova.tests.baremetal import bmdb as bmdb_utils


LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS

class FakeVifDriver(object):
    def plug(self, instance, network, mapping):
        pass
    def unplug(self, instance, network, mapping):
        pass

FakeFirewallDriver = NoopFirewallDriver

class FakeVolumeDriver(object):
    pass

HOST = bmdb_utils.new_phy_host(cpus=2, memory_mb=4096, service_id=100)
NICS = [
        { 'address': '01:23:45:67:89:01', 'datapath_id': '0x1', 'port_no': 1, },
        { 'address': '01:23:45:67:89:02', 'datapath_id': '0x2', 'port_no': 2, },
        ]

def class_path(class_):
    return class_.__module__ + '.' + class_.__name__


class BaremetalConnectionTestCase(test.TestCase):

    def setUp(self):
        super(BaremetalConnectionTestCase, self).setUp()
        self.flags(baremetal_sql_connection='sqlite:///:memory:',
                   host='test',
                   baremetal_driver='fake',
                   physical_vif_driver=class_path(FakeVifDriver),
                   baremetal_firewall_driver=class_path(FakeFirewallDriver),
                   baremetal_volume_driver=class_path(FakeVolumeDriver),
                   power_manager='dummy',
                   )
        bmdb_utils.clear_tables()
        context = test_utils.get_test_admin_context()
        host = bmdb.phy_host_create(context, HOST)
        self.host_id = host['id']
        for nic in NICS:
            bmdb.phy_interface_create(context,
                                      host['id'],
                                      nic['address'],
                                      nic['datapath_id'],
                                      nic['port_no'])
        db.service_create(context,
                          {
                           'id': HOST['service_id'],
                           'host': 'test',
                           'topic': 'compute',
                           })

    def tearDown(self):
        super(BaremetalConnectionTestCase, self).tearDown()
    
    def test_loading_baremetal_drivers(self):
        from nova.virt.baremetal import fake
        drv = c.BareMetalDriver()
        self.assertTrue(isinstance(drv.baremetal_nodes, fake.BareMetalNodes))
        self.assertTrue(isinstance(drv._vif_driver, FakeVifDriver))
        self.assertTrue(isinstance(drv._firewall_driver, FakeFirewallDriver))
        self.assertTrue(isinstance(drv._volume_driver, FakeVolumeDriver))

    def test_spawn(self):
        context = test_utils.get_test_admin_context()
        instance = test_utils.get_test_instance()
        instance['id'] = 12345
        network_info = test_utils.get_test_network_info()
        block_device_info = None
        image_meta = test_utils.get_test_image_info(None, instance)

        from nova.virt.baremetal import nodes
        from nova.virt.phy import fake
        self.mox.StubOutWithMock(nodes, 'get_baremetal_nodes')
        nodes.get_baremetal_nodes().AndReturn(fake.Fake())
        self.mox.ReplayAll()
    
        drv = c.BareMetalDriver()
        drv.spawn(context, instance=instance,
                  image_meta=image_meta,
                  network_info=network_info,
                  block_device_info=block_device_info)
        self.mox.VerifyAll()
        
        h = bmdb.phy_host_get(context, self.host_id)
        self.assertEqual(h['instance_id'], instance['id'])
        self.assertEqual(h['task_state'], physical_states.ACTIVE)
    
    def test_get_host_stats(self):
        self.flags(instance_type_extra_specs=['cpu_arch:x86_64', 'x:123', 'y:456',],
                   baremetal_driver='fake')
        drv = c.BareMetalDriver()
        s = drv._get_host_stats()
        es = s['instance_type_extra_specs']
        self.assertEqual(es['cpu_arch'], 'x86_64')
        self.assertEqual(es['x'], '123')
        self.assertEqual(es['y'], '456')
        self.assertEqual(es['hypervisor_type'], 'baremetal')
        self.assertEqual(es['baremetal_driver'], 'fake')
        self.assertEqual(len(es), 5)


class FindHostTestCase(test.TestCase):
    
    def test_find_suitable_phy_host_verify(self):
        h1 = bmdb_utils.new_phy_host(id=1, memory_mb=512)
        h2 = bmdb_utils.new_phy_host(id=2, memory_mb=2048)
        h3 = bmdb_utils.new_phy_host(id=3, memory_mb=1024)
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
        h1 = bmdb_utils.new_phy_host(id=1, memory_mb=512)
        h2 = bmdb_utils.new_phy_host(id=2, memory_mb=2048)
        h3 = bmdb_utils.new_phy_host(id=3, memory_mb=1024)
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
        h1 = bmdb_utils.new_phy_host(id=1, cpus=1, memory_mb=512)
        h2 = bmdb_utils.new_phy_host(id=2, cpus=2, memory_mb=512)
        h3 = bmdb_utils.new_phy_host(id=3, cpus=3, memory_mb=512)
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
