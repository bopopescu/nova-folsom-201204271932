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

"""Baremetal DB utils for test."""

""" start add by NTT DOCOMO """

from nova import flags
from nova import test
from nova import context as nova_context
from nova.virt.baremetal import bmdb
from nova.virt.baremetal.bmdb.sqlalchemy import baremetal_models

flags.DECLARE('baremetal_sql_connection', 'nova.virt.baremetal.bmdb.sqlalchemy.baremetal_session')
    
def new_phy_host(**kwargs):
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

class BMDBTestCase(test.TestCase):
    
    def setUp(self):
        super(BMDBTestCase, self).setUp()
        self.flags(baremetal_sql_connection='sqlite:///:memory:')
        baremetal_models.unregister_models()
        baremetal_models.register_models()
        self.context = nova_context.get_admin_context()
    

""" end add by NTT DOCOMO """
