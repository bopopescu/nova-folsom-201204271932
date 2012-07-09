# Copyright (c) 2012 NTT DOCOMO, INC. 
# Copyright (c) 2011 OpenStack, LLC.
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
Manage hosts in the current zone.
"""

import datetime
import UserDict

from nova import db
from nova import exception
from nova import flags
from nova import log as logging
from nova.openstack.common import cfg
from nova.scheduler import filters
from nova import utils

""" start add by NTT DOCOMO """
import pprint
PP=pprint.PrettyPrinter(indent=4)
from nova.virt.baremetal import bmdb
from nova import context as ctx
from nova.scheduler import host_manager
import operator

def _as_dict(o):
    if isinstance(o, dict):
        return o
    else:
        return o.__dict__

""" end add by NTT DOCOMO """

host_manager_opts = []

FLAGS = flags.FLAGS
FLAGS.register_opts(host_manager_opts)
LOG = logging.getLogger(__name__)

class ReadOnlyDict(UserDict.IterableUserDict):
    """A read-only dict."""
    def __init__(self, source=None):
        self.data = {}
        self.update(source)
        
    def __setitem__(self, key, item):
        raise TypeError

    def __delitem__(self, key):
        raise TypeError

    def clear(self):
        raise TypeError

    def pop(self, key, *args):
        raise TypeError

    def popitem(self):
        raise TypeError

    def update(self, source=None):
        if source is None:
            return
        elif isinstance(source, UserDict.UserDict):
            self.data = source.data
        elif isinstance(source, type({})):
            self.data = source
        else:
            raise TypeError

class BaremetalHostState(host_manager.HostState):
    """Mutable and immutable information tracked for a host.
    This is an attempt to remove the ad-hoc data structures
    previously used and lock down access.
    """
    def __init__(self, host, topic, capabilities=None, service=None):
        self.host = host
        self.topic = topic
                
        # Read-only capability dicts

        if capabilities is None:
            capabilities = {}
        self.capabilities = ReadOnlyDict(capabilities.get(topic, None))
        
        """ start add by NTT DOCOMO """
        self.available_hosts = []
        self.physical_compute = False
        
        extra_type = self.capabilities.get('type', None)
        if extra_type == "physical":
            self.physical_compute = True
        """ end add by NTT DOCOMO """
        
        if service is None:
            service = {}
        self.service = ReadOnlyDict(service)
        
        # Mutable available resources.
        # These will change as resources are virtually "consumed".
        self.free_ram_mb = 0
        self.free_disk_mb = 0
        self.vcpus_total = 0
        self.vcpus_used = 0

    """ start add by NTT DOCOMO """
    def update_from_compute_node(self, compute, context=None):
        """Update information about a host from its compute_node info."""
        
        if self.physical_compute:
            phy_hosts = bmdb.phy_host_get_all_by_service_id(context, compute['service_id'])
            LOG.debug("point0.1: self=%s, phy_hosts=%s", str(self), PP.pformat(phy_hosts))
            
            for host in phy_hosts:
                if not host['instance_id']:
                    self.available_hosts.append(host)
                    
            """those sorting should be decided by weight in a scheduler """
            self.available_hosts = sorted(self.available_hosts, key=operator.itemgetter('memory_mb'), reverse=True)
            self.available_hosts = sorted(self.available_hosts, key=operator.itemgetter('cpus'), reverse=True)
            
            LOG.debug("point0.2: self=%s available_hosts=%s", str(self), PP.pformat(self.available_hosts))
              
            if len(self.available_hosts):
                phy_host = self.available_hosts[0]
                LOG.debug("point0.2.1: phy_hosts=%s", PP.pformat(phy_host))
            else:
                phy_host = {}
                phy_host['local_gb'] = 0
                phy_host['memory_mb'] = 0
                phy_host['cpus'] = 0
                
            all_disk_mb = phy_host['local_gb'] * 1024
            all_ram_mb = phy_host['memory_mb']
            vcpus_total = phy_host['cpus']
        
        else: 
            all_disk_mb = compute['local_gb'] * 1024
            all_ram_mb = compute['memory_mb']
            vcpus_total = compute['vcpus']
            if FLAGS.reserved_host_disk_mb > 0:
                all_disk_mb -= FLAGS.reserved_host_disk_mb
            if FLAGS.reserved_host_memory_mb > 0:
                all_ram_mb -= FLAGS.reserved_host_memory_mb
            
        self.free_ram_mb = all_ram_mb
        self.free_disk_mb = all_disk_mb
        self.vcpus_total = vcpus_total
        
        LOG.debug("point0.3: self=%s free_ram_mb=%f free_disk_mb=%f vcpus_total=%f", str(self), self.free_ram_mb, self.free_disk_mb, self.vcpus_total)
        
        """ end add by NTT DOCOMO """
        
    def consume_from_instance(self, instance):
        """Update information about a host from instance info."""
        
        """ start add by NTT DOCOMO """
        if self.physical_compute:
            LOG.debug("instance=%s", str(instance))
            context = ctx.get_admin_context()
            instance_id = instance.get('id', None)
            if instance_id:
                phy_host = bmdb.phy_host_get_by_instance_id(context, instance['id'])
            else:
                phy_host = None    
                
            if phy_host:
                return
            elif len(self.available_hosts):
		consumed_host = self.available_hosts.pop(0)
                LOG.debug("point1.0.1: self=%s consumed_host=%s", str(self), PP.pformat(_as_dict(consumed_host)))
            if len(self.available_hosts):
                phy_host = self.available_hosts[0]
                LOG.debug("point1.0.2: self=%s phy_hosts=%s", str(self), PP.pformat(_as_dict(phy_host)))
 
            else:
                phy_host = {}
                phy_host['local_gb'] = 0
                phy_host['memory_mb'] = 0
                phy_host['cpus'] = 0
            
            self.free_disk_mb = phy_host['local_gb'] * 1024
            self.free_ram_mb = phy_host['memory_mb']
            self.vcpus_used = 0
            self.vcpus_total = phy_host['cpus']
        else:
            disk_mb = (instance['root_gb'] + instance['ephemeral_gb']) * 1024
            ram_mb = instance['memory_mb']
            vcpus = instance['vcpus']
            self.free_ram_mb -= ram_mb
            self.free_disk_mb -= disk_mb
            self.vcpus_used += vcpus
            
        LOG.debug("point1.1: self=%s free_ram_mb=%f free_disk_mb=%f vcpus_total=%f", str(self), self.free_ram_mb, self.free_disk_mb, self.vcpus_total)
        """ end add by NTT DOCOMO """

class BaremetalHostManager(host_manager.HostManager):
    """Base HostManager class."""

    # Can be overriden in a subclass
    host_state_cls = BaremetalHostState

    """ start add by NTT DOCOMO """
    """ Make HostManager to a singleton object """
    def __new__(self):
        if not hasattr(self, "__instance__"):
            self.__instance__ = super(BaremetalHostManager, self).__new__(self)
        return self.__instance__
    """ end add by NTT DOCOMO """

    def __init__(self):
        self.service_states = {}  # { <host> : { <service> : { cap k : v }}}
        self.filter_classes = filters.get_filter_classes(
                FLAGS.scheduler_available_filters)
    
    def get_all_host_states(self, context, topic):
        """Returns a dict of all the hosts the HostManager
        knows about. Also, each of the consumable resources in HostState
        are pre-populated and adjusted based on data in the db.

        For example:
        {'192.168.1.100': HostState(), ...}

        Note: this can be very slow with a lot of instances.
        InstanceType table isn't required since a copy is stored
        with the instance (in case the InstanceType changed since the
        instance was created)."""

        if topic != 'compute':
            raise NotImplementedError(_(
                "host_manager only implemented for 'compute'"))

        host_state_map = {}

        # Make a compute node dict with the bare essential metrics.
        compute_nodes = db.compute_node_get_all(context)
        for compute in compute_nodes:
            service = compute['service']
            if not service:
                LOG.warn(_("No service for compute ID %s") % compute['id'])
                continue
            host = service['host']
            capabilities = self.service_states.get(host, None)
            host_state = self.host_state_cls(host, topic,
                    capabilities=capabilities,
                    service=dict(service.iteritems()))
            """ start add by DOCOMO """
            # pass context to access DB
            host_state.update_from_compute_node(compute, context=context)
            """ end add by DOCOMO """
            host_state_map[host] = host_state

        # "Consume" resources from the host the instance resides on.
        instances = db.instance_get_all(context)
        for instance in instances:
            host = instance['host']
            if not host:
                continue
            host_state = host_state_map.get(host, None)
            if not host_state:
                continue
            host_state.consume_from_instance(instance)
        return host_state_map
