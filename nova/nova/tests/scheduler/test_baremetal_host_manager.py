# Copyright (c) 2011 OpenStack, LLC
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
Tests For BaremetalHostManager
"""

import datetime

from nova.virt.baremetal import bmdb
from nova import db
from nova import exception
from nova import flags
from nova.scheduler import baremetal_host_manager
from nova import test
from nova.tests.scheduler import fakes
from nova import utils

FLAGS = flags.FLAGS


BAREMETAL_COMPUTE_NODES = [
        dict(id=1, service_id=1, local_gb=10240, memory_mb=10240, vcpus=10,
                service=dict(host='host1', disabled=False)),
        dict(id=2, service_id=2, local_gb=2048, memory_mb=1024, vcpus=2,
                service=dict(host='host2', disabled=True)),
        dict(id=3, service_id=3, local_gb=2048, memory_mb=2048, vcpus=2,
                service=dict(host='host3', disabled=True)),
        dict(id=4, service_id=4, local_gb=2048, memory_mb=2048, vcpus=2,
                service=dict(host='host4', disabled=True)),
        # Broken entry
        dict(id=5, service_id=5, local_gb=1024, memory_mb=1024, vcpus=1, service=None),
]

BAREMETAL_INSTANCES = [
        dict(root_gb=512, ephemeral_gb=0, memory_mb=512, vcpus=1, host='host1'),
        dict(root_gb=512, ephemeral_gb=0, memory_mb=512, vcpus=1, host='host1'),
        dict(root_gb=512, ephemeral_gb=0, memory_mb=512, vcpus=2, host='host2'),
        dict(root_gb=512, ephemeral_gb=0, memory_mb=512, vcpus=3, host='host3'),
        dict(root_gb=512, ephemeral_gb=0, memory_mb=512, vcpus=4, host='host4'),
        dict(root_gb=512, ephemeral_gb=0, memory_mb=512, vcpus=2, host='host4'),
        dict(root_gb=512, ephemeral_gb=0, memory_mb=512, vcpus=1, host='host3'),
        dict(root_gb=512, ephemeral_gb=0, memory_mb=512, vcpus=1, host='host2'),
        dict(root_gb=512, ephemeral_gb=0, memory_mb=512, vcpus=3, host='host1'),
        # Broken host
        dict(root_gb=1024, ephemeral_gb=0, memory_mb=1024, vcpus=1, host=None),
        # No matching host
        dict(root_gb=1024, ephemeral_gb=0, memory_mb=1024, vcpus=1, host='hostz'),
]

BAREMETAL_HOSTS = [
        dict(cpus=1, instance_id=None, ipmi_address='172.27.2.110', memory_mb=512, local_gb=0),
        dict(cpus=1, instance_id=None, ipmi_address='172.27.2.110', memory_mb=2048, local_gb=0),
]

BAREMETAL_HOSTS_1 = [
        dict(cpus=1, instance_id=None, ipmi_address='172.27.2.111', memory_mb=512, local_gb=0),
        dict(cpus=1, instance_id=None, ipmi_address='172.27.2.111', memory_mb=1024, local_gb=0),
        dict(cpus=2, instance_id=None, ipmi_address='172.27.2.111', memory_mb=2048, local_gb=0),
        dict(cpus=2, instance_id=None, ipmi_address='172.27.2.111', memory_mb=1024, local_gb=0),
        dict(cpus=3, instance_id=None, ipmi_address='172.27.2.111', memory_mb=4096, local_gb=0),
        dict(cpus=3, instance_id=None, ipmi_address='172.27.2.111', memory_mb=8192, local_gb=0),
        # No matching host
        dict(cpus=1, instance_id=1, ipmi_address='172.27.2.111', memory_mb=512, local_gb=0),
        dict(cpus=4, instance_id=1, ipmi_address='172.27.2.111', memory_mb=10240, local_gb=0),
]

BAREMETAL_HOSTS_2 = [
        dict(cpus=3, instance_id=None, ipmi_address='172.27.2.112', memory_mb=2048, local_gb=0),
        dict(cpus=4, instance_id=None, ipmi_address='172.27.2.112', memory_mb=1024, local_gb=0),
        dict(cpus=2, instance_id=None, ipmi_address='172.27.2.112', memory_mb=512, local_gb=0),
        dict(cpus=3, instance_id=None, ipmi_address='172.27.2.112', memory_mb=8192, local_gb=0),
        dict(cpus=4, instance_id=None, ipmi_address='172.27.2.112', memory_mb=1024, local_gb=0),
        dict(cpus=2, instance_id=None, ipmi_address='172.27.2.112', memory_mb=4096, local_gb=0),
        # No matching host
        dict(cpus=1, instance_id=2, ipmi_address='172.27.2.112', memory_mb=512, local_gb=0),
        dict(cpus=4, instance_id=2, ipmi_address='172.27.2.112', memory_mb=10240, local_gb=0),
]

BAREMETAL_HOSTS_3 = [
        dict(cpus=4, instance_id=None, ipmi_address='172.27.2.113', memory_mb=512, local_gb=0),
        dict(cpus=4, instance_id=None, ipmi_address='172.27.2.113', memory_mb=2048, local_gb=0),
        dict(cpus=5, instance_id=None, ipmi_address='172.27.2.113', memory_mb=8192, local_gb=0),
        dict(cpus=5, instance_id=None, ipmi_address='172.27.2.113', memory_mb=1024, local_gb=0),
        # No matching host
        dict(cpus=1, instance_id=3, ipmi_address='172.27.2.113', memory_mb=512, local_gb=0),
        dict(cpus=4, instance_id=3, ipmi_address='172.27.2.113', memory_mb=10240, local_gb=0),
]


BAREMETAL_HOSTS_4 = [
        dict(cpus=5, instance_id=None, ipmi_address='172.27.2.114', memory_mb=512, local_gb=0),
        dict(cpus=5, instance_id=None, ipmi_address='172.27.2.114', memory_mb=8192, local_gb=0),
        dict(cpus=6, instance_id=None, ipmi_address='172.27.2.114', memory_mb=512, local_gb=0),
        dict(cpus=6, instance_id=None, ipmi_address='172.27.2.114', memory_mb=8192, local_gb=0),
        # No matching host
        dict(cpus=1, instance_id=4, ipmi_address='172.27.2.114', memory_mb=512, local_gb=0),
        dict(cpus=4, instance_id=4, ipmi_address='172.27.2.114', memory_mb=10240, local_gb=0),
]


class ComputeFilterClass1(object):
    def host_passes(self, *args, **kwargs):
        pass


class ComputeFilterClass2(object):
    def host_passes(self, *args, **kwargs):
        pass


class BaremetalHostManagerTestCase(test.TestCase):
    """Test case for HostManager class"""

    def setUp(self):
        super(BaremetalHostManagerTestCase, self).setUp()
        self.baremetal_host_manager = baremetal_host_manager.BaremetalHostManager()

    def test_choose_host_filters_not_found(self):
        self.flags(scheduler_default_filters='ComputeFilterClass3')
        self.baremetal_host_manager.filter_classes = [ComputeFilterClass1,
                ComputeFilterClass2]
        self.assertRaises(exception.SchedulerHostFilterNotFound,
                self.baremetal_host_manager._choose_host_filters, None)

    def test_choose_host_filters(self):
        self.flags(scheduler_default_filters=['ComputeFilterClass2'])
        self.baremetal_host_manager.filter_classes = [ComputeFilterClass1,
                ComputeFilterClass2]

        # Test 'compute' returns 1 correct function
        filter_fns = self.baremetal_host_manager._choose_host_filters(None)
        self.assertEqual(len(filter_fns), 1)
        self.assertEqual(filter_fns[0].__func__,
                ComputeFilterClass2.host_passes.__func__)

    def test_filter_hosts(self):
        topic = 'fake_topic'

        filters = ['fake-filter1', 'fake-filter2']
        fake_host1 = baremetal_host_manager.BaremetalHostState('host1', topic)
        fake_host2 = baremetal_host_manager.BaremetalHostState('host2', topic)
        hosts = [fake_host1, fake_host2]
        filter_properties = 'fake_properties'

        self.mox.StubOutWithMock(self.baremetal_host_manager,
                '_choose_host_filters')
        self.mox.StubOutWithMock(fake_host1, 'passes_filters')
        self.mox.StubOutWithMock(fake_host2, 'passes_filters')

        self.baremetal_host_manager._choose_host_filters(None).AndReturn(filters)
        fake_host1.passes_filters(filters, filter_properties).AndReturn(
                False)
        fake_host2.passes_filters(filters, filter_properties).AndReturn(
                True)

        self.mox.ReplayAll()
        filtered_hosts = self.baremetal_host_manager.filter_hosts(hosts,
                filter_properties, filters=None)
        self.assertEqual(len(filtered_hosts), 1)
        self.assertEqual(filtered_hosts[0], fake_host2)
        self.mox.VerifyAll()

    def test_update_service_capabilities(self):
        service_states = self.baremetal_host_manager.service_states
        self.assertDictMatch(service_states, {})
        self.mox.StubOutWithMock(utils, 'utcnow')
        utils.utcnow().AndReturn(31337)
        utils.utcnow().AndReturn(31338)
        utils.utcnow().AndReturn(31339)

        host1_compute_capabs = dict(free_memory=1234, host_memory=5678,
                timestamp=1, type='physical')
        host1_volume_capabs = dict(free_disk=4321, timestamp=1)
        host2_compute_capabs = dict(free_memory=8756, timestamp=1, type='physical')

        self.mox.ReplayAll()
        self.baremetal_host_manager.update_service_capabilities('compute', 'host1',
                host1_compute_capabs)
        self.baremetal_host_manager.update_service_capabilities('volume', 'host1',
                host1_volume_capabs)
        self.baremetal_host_manager.update_service_capabilities('compute', 'host2',
                host2_compute_capabs)

        # Make sure dictionary isn't re-assigned
        self.assertEqual(self.baremetal_host_manager.service_states, service_states)
        # Make sure original dictionary wasn't copied
        self.assertEqual(host1_compute_capabs['timestamp'], 1)
        self.assertEqual(host1_compute_capabs['type'], 'physical')

        host1_compute_capabs['timestamp'] = 31337
        host1_volume_capabs['timestamp'] = 31338
        host2_compute_capabs['timestamp'] = 31339

        expected = {'host1': {'compute': host1_compute_capabs,
                              'volume': host1_volume_capabs},
                    'host2': {'compute': host2_compute_capabs}}
        self.assertDictMatch(service_states, expected)
        self.mox.VerifyAll()

    def test_host_service_caps_stale(self):
        self.flags(periodic_interval=5)

        host1_compute_capabs = dict(free_memory=1234, host_memory=5678,
                timestamp=datetime.datetime.fromtimestamp(3000), type='physical')
        host1_volume_capabs = dict(free_disk=4321,
                timestamp=datetime.datetime.fromtimestamp(3005))
        host2_compute_capabs = dict(free_memory=8756,
                timestamp=datetime.datetime.fromtimestamp(3010))

        service_states = {'host1': {'compute': host1_compute_capabs,
                                    'volume': host1_volume_capabs},
                          'host2': {'compute': host2_compute_capabs}}

        self.baremetal_host_manager.service_states = service_states

        self.mox.StubOutWithMock(utils, 'utcnow')
        utils.utcnow().AndReturn(datetime.datetime.fromtimestamp(3020))
        utils.utcnow().AndReturn(datetime.datetime.fromtimestamp(3020))
        utils.utcnow().AndReturn(datetime.datetime.fromtimestamp(3020))

        self.mox.ReplayAll()
        res1 = self.baremetal_host_manager.host_service_caps_stale('host1', 'compute')
        res2 = self.baremetal_host_manager.host_service_caps_stale('host1', 'volume')
        res3 = self.baremetal_host_manager.host_service_caps_stale('host2', 'compute')

        self.assertEqual(res1, True)
        self.assertEqual(res2, False)
        self.assertEqual(res3, False)
        self.mox.VerifyAll()

    def test_delete_expired_host_services(self):
        host1_compute_capabs = dict(free_memory=1234, host_memory=5678,
                timestamp=datetime.datetime.fromtimestamp(3000))
        host1_volume_capabs = dict(free_disk=4321,
                timestamp=datetime.datetime.fromtimestamp(3005))
        host2_compute_capabs = dict(free_memory=8756,
                timestamp=datetime.datetime.fromtimestamp(3010), type='physical')

        service_states = {'host1': {'compute': host1_compute_capabs,
                                    'volume': host1_volume_capabs},
                          'host2': {'compute': host2_compute_capabs}}
        self.baremetal_host_manager.service_states = service_states

        to_delete = {'host1': {'volume': host1_volume_capabs},
                     'host2': {'compute': host2_compute_capabs}}

        self.baremetal_host_manager.delete_expired_host_services(to_delete)
        # Make sure dictionary isn't re-assigned
        self.assertEqual(self.baremetal_host_manager.service_states, service_states)

        expected = {'host1': {'compute': host1_compute_capabs}}
        self.assertEqual(service_states, expected)

    def test_get_service_capabilities(self):
        host1_compute_capabs = dict(free_memory=1000, host_memory=5678,
                timestamp=datetime.datetime.fromtimestamp(3000))
        host1_volume_capabs = dict(free_disk=4321,
                timestamp=datetime.datetime.fromtimestamp(3005))
        host2_compute_capabs = dict(free_memory=8756,
                timestamp=datetime.datetime.fromtimestamp(3010))
        host2_volume_capabs = dict(free_disk=8756,
                enabled=False,
                timestamp=datetime.datetime.fromtimestamp(3010))
        host3_compute_capabs = dict(free_memory=1234, host_memory=4000,
                timestamp=datetime.datetime.fromtimestamp(3010))
        host3_volume_capabs = dict(free_disk=2000,
                timestamp=datetime.datetime.fromtimestamp(3010))

        service_states = {'host1': {'compute': host1_compute_capabs,
                                    'volume': host1_volume_capabs},
                          'host2': {'compute': host2_compute_capabs,
                                    'volume': host2_volume_capabs},
                          'host3': {'compute': host3_compute_capabs,
                                    'volume': host3_volume_capabs}}
        self.baremetal_host_manager.service_states = service_states

        info = {'called': 0}

        # This tests with 1 volume disabled (host2), and 1 volume node
        # as stale (host1)
        def _fake_host_service_caps_stale(host, service):
            info['called'] += 1
            if host == 'host1':
                if service == 'compute':
                    return False
                elif service == 'volume':
                    return True
            elif host == 'host2':
                # Shouldn't get here for 'volume' because the service
                # is disabled
                self.assertEqual(service, 'compute')
                return False
            self.assertEqual(host, 'host3')
            return False

        self.stubs.Set(self.baremetal_host_manager, 'host_service_caps_stale',
                _fake_host_service_caps_stale)

        self.mox.StubOutWithMock(self.baremetal_host_manager,
                'delete_expired_host_services')
        self.baremetal_host_manager.delete_expired_host_services({'host1': ['volume']})

        self.mox.ReplayAll()
        result = self.baremetal_host_manager.get_service_capabilities()

        self.assertEqual(info['called'], 5)

        # only 1 volume node active == 'host3', so min/max is 2000
        expected = {'volume_free_disk': (2000, 2000),
                    'compute_host_memory': (4000, 5678),
                    'compute_free_memory': (1000, 8756)}

        self.assertDictMatch(result, expected)
        
        self.mox.VerifyAll()

    def test_get_all_host_states(self):
        self.flags(reserved_host_memory_mb=512,
                reserved_host_disk_mb=1024)

        context = 'fake_context'
        topic = 'compute'
        #compute['service_id'] = 1
        #instance['id'] = 1

        self.mox.StubOutWithMock(db, 'compute_node_get_all')
        self.mox.StubOutWithMock(baremetal_host_manager.LOG, 'warn')
        self.mox.StubOutWithMock(db, 'instance_get_all')
        #self.mox.StubOutWithMock(bmdb, 'phy_host_get_by_instance_id')
        
        #self.mox.StubOutWithMock(utils, 'utcnow')
        #utils.utcnow().AndReturn(31337)
        self.stubs.Set(utils, 'utcnow', lambda: 31337)
        
        def _fake_phy_host_get_all_by_service_id(context, service_id):
            if service_id == 1:
                return BAREMETAL_HOSTS_1
            elif service_id == 2:
                return BAREMETAL_HOSTS_2
            elif service_id == 3:
                return BAREMETAL_HOSTS_3
            elif service_id == 4:
                return BAREMETAL_HOSTS_4
            else:
                return {}
             
        def _fake_phy_host_get_by_instance_id(context, instance_id):
            return None  
                
        self.stubs.Set(bmdb, 'phy_host_get_all_by_service_id', _fake_phy_host_get_all_by_service_id)
        self.stubs.Set(bmdb, 'phy_host_get_by_instance_id', _fake_phy_host_get_by_instance_id)
        
        #self.mox.StubOutWithMock(bmdb, 'phy_host_get_all_by_service_id')
        #bmdb.phy_host_get_all_by_service_id(context, compute['service_id']).AndReturn(BAREMETAL_HOSTS)
        
        db.compute_node_get_all(context).AndReturn(BAREMETAL_COMPUTE_NODES)
        
        # Invalid service
        baremetal_host_manager.LOG.warn("No service for compute ID 5")
        db.instance_get_all(context).AndReturn(BAREMETAL_INSTANCES)
        self.mox.ReplayAll()
        
        host1_compute_capabs = dict(free_memory=1234, host_memory=5678, timestamp=1)
        host2_compute_capabs = dict(free_memory=1234, host_memory=5678, timestamp=1, type='physical')
        self.baremetal_host_manager.update_service_capabilities('compute', 'host1', host1_compute_capabs)
        self.baremetal_host_manager.update_service_capabilities('compute', 'host2', host2_compute_capabs)
        self.baremetal_host_manager.update_service_capabilities('compute', 'host3', host2_compute_capabs)
        self.baremetal_host_manager.update_service_capabilities('compute', 'host4', host2_compute_capabs)
 
	host_states = self.baremetal_host_manager.get_all_host_states(context, topic)
        
        num_bm_nodes = len(BAREMETAL_COMPUTE_NODES)
        
        # not contains broken entry
        self.assertEqual(len(host_states), num_bm_nodes - 1)
        self.assertIn('host1', host_states)
        self.assertIn('host2', host_states)
        self.assertIn('host3', host_states)
        self.assertIn('host4', host_states)
        
        # check returned value
        # host1 : subtract total ram of BAREMETAL_INSTANCES from BAREMETAL_COMPUTE_NODES
        # host1 : total vcpu of BAREMETAL_INSTANCES
        self.assertEqual(host_states['host1'].free_ram_mb + FLAGS.reserved_host_memory_mb, 8704)
        self.assertEqual(host_states['host1'].vcpus_used, 5)

        # host2 : subtract BAREMETAL_INSTANCES from BAREMETAL_HOSTS_2
        # host2 : total vcpu of BAREMETAL_INSTANCES
        self.assertEqual(host_states['host2'].free_ram_mb, 8192)
        self.assertEqual(host_states['host2'].vcpus_total, 3)

        # host3 : subtract BAREMETAL_INSTANCES from BAREMETAL_HOSTS_3
        # host3 : total vcpu of BAREMETAL_INSTANCES
        self.assertEqual(host_states['host3'].free_ram_mb, 2048)
        self.assertEqual(host_states['host3'].vcpus_total, 4)

        # host4 : subtract BAREMETAL_INSTANCES from BAREMETAL_HOSTS_4
        # host4 : total vcpu of BAREMETAL_INSTANCES
        self.assertEqual(host_states['host4'].free_ram_mb, 8192)
        self.assertEqual(host_states['host4'].vcpus_total, 5)

        self.mox.VerifyAll()
