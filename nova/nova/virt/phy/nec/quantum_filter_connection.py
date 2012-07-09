# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright (c) 2012 NTT DOCOMO, INC. 
# Copyright 2011 Nicira Networks
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

""" start mod by NTT DOCOMO """

from nova import flags
from nova import log as logging
from nova.virt.phy.nec import filter_client as quantum_filter_client


LOG = logging.getLogger(__name__)

flags.DECLARE('quantum_connection_host', 'nova.network.quantum.quantum_connection')
flags.DECLARE('quantum_connection_port', 'nova.network.quantum.quantum_connection')

FLAGS = flags.FLAGS

def _filters_dict_into_list(filters):
    l = []
    for f in filters.get('filters', {}):
        fid = f.get('id')
        if fid:
            l.append(fid)
    return l
            

class QuantumFilterClientConnection(object):
    """Abstracts connection to Quantum service into higher level
       operations performed by the QuantumManager.

       Separating this out as a class also let's us create a 'fake'
       version of this class for unit tests.
    """

    def __init__(self):
        """Initialize Quantum client class based on flags."""
        self.client = quantum_filter_client.FilterClient(
                FLAGS.quantum_connection_host,
                FLAGS.quantum_connection_port,
                format="json",
                logger=LOG)

    def create_filter(self, tenant_id, network_id, filter_body):
        resdict = self.client.create_filter(tenant_id, network_id, filter_body)
        return resdict["filter"]["id"]

    def delete_filter(self, tenant_id, network_id, filter_id):
        self.client.delete_filter(tenant_id, network_id, filter_id)

    def list_filters(self, tenant_id, network_id):
        r = self.client.list_filters(tenant_id, network_id)
        return _filters_dict_into_list(r)

    def show_filter(self, tenant_id, network_id, filter_id):
        r = self.client.show_filter_details(tenant_id, network_id, filter_id)
        return r


class FakeQuantumFilterClientConnection(object):
    """Abstracts connection to Quantum service into higher level
       operations performed by the QuantumManager.

       Separating this out as a class also let's us create a 'fake'
       version of this class for unit tests.
    """

    def __init__(self):
        self.next_id = 1
        self.filters = {}
        pass

    def create_filter(self, tenant_id, network_id, filter_body):
        d = {
             'tenant_id': tenant_id,
             'network_id': network_id,
             'filter': filter_body,
            }
        filter_id = str(self.next_id)
        self.next_id += 1
        self.filters[filter_id] = d
        LOG.info("added filter: id=%s, %s", filter_id, d)
        return filter_id

    def delete_filter(self, tenant_id, network_id, filter_id):
        LOG.info("delete filter id=%s", filter_id)
        f = self.filters.get(filter_id)
        if not f:
            LOG.warn("filter id=%s not found", filter_id)
        if f.get('tenant_id') != tenant_id:
            LOG.warn("filter.id=%s: filter.tenant_id=%s != %s",
                     filter_id,
                     f('tenant_id'),
                     tenant_id)
            return
        if f.get('network_id') != network_id:
            LOG.warn("filter.id=%s: filter.network_id=%s != %s",
                     filter_id,
                     f.get('network_id'),
                     network_id)
            return
        del self.filters[filter_id]
        LOG.info("deleted filter: id=%s, %s", filter_id, f)

    def list_filters(self, tenant_id, network_id):
        l = []
        for (fid,d) in self.filters.iteritems():
            if d['tenant_id'] == tenant_id and d['network_id'] == network_id:
                l.append(fid)
        return l

    def show_filter(self, tenant_id, network_id, filter_id):
        f = self.filters.get(filter_id, {})
        if f.get('tenant_id') == tenant_id and f.get('network_id') == network_id:
            return f
        return None

""" end mod by NTT DOCOMO """