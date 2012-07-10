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

from webob import exc

from nova import context
from nova import db
from nova import flags
from nova import log as logging
from nova.openstack.common import cfg
from nova import utils
from nova.virt import firewall
from nova.network.quantum.quantum_connection import QuantumClientConnection


LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS

nec_firewall_opts = [ 
    cfg.StrOpt('physical_quantum_filter_connection',
               default='nova.virt.phy.quantum_filter_connection.QuantumFilterClientConnection',
               help='Filter connection class for physical instances'),
    ]

FLAGS.register_opts(nec_firewall_opts)

DROP_DHCP_SERVER_PRIORITY  = 10060
ALLOW_DHCP_CLIENT_PRIORITY = 10050
ALLOW_SOURCE_PRIORITY      = 10040
DROP_ALL_PRIORITY          = 10030
SECURITY_GROUP_PRIORITY    = 10020
DEFAULT_DROP_PRIORITY      = 10010
DEFAULT_ACCEPT_PRIORITY    = 10000

def _get_vifinfo_uuid(tenant_id, vif_uuid):
    try:
        qc = QuantumClientConnection()
        network_uuid,vifinfo_uuid = qc.get_port_by_attachment(tenant_id, vif_uuid)
        LOG.debug("vif_uuid:%s -> vifinfo_uuid:%s", vif_uuid, vifinfo_uuid)
        return vifinfo_uuid
    except exc.HTTPNotFound:
        LOG.excption("show_vifinfo(%s): throws (return None)", vif_uuid)
        return None

def _build_deny_dhcp_server(in_port):
    c = dict(in_port=in_port,
             protocol='udp',
             src_port=67,
             dst_port=68 )
    f = dict(condition=c,
             action='DROP',
             priority=DROP_DHCP_SERVER_PRIORITY )
    return [ dict(filter=f) ]

def _build_allow_dhcp_client(in_port, mac):
    c = dict(in_port=in_port,
             src_mac=mac,
             protocol='udp',
             src_port=68,
             dst_port=67 )
    f = dict(condition=c,
             action='ACCEPT',
             priority=ALLOW_DHCP_CLIENT_PRIORITY )
    return [ dict(filter=f) ]

def _build_allow_src(in_port, mac, cidr):
    c = dict(in_port=in_port,
             src_mac=mac,
             src_cidr=cidr )
    f = dict(condition=c,
             action='ACCEPT',
             priority=ALLOW_SOURCE_PRIORITY )
    return [ dict(filter=f) ]

def _build_deny_all(in_port):
    c = dict(in_port=in_port)
    f = dict(condition=c,
             action='DROP',
             priority=DROP_ALL_PRIORITY )
    return [ dict(filter=f) ]

def _build_security_group_rule_filter(dst_cidr, rule, priority):
    filter_bodys = []
    from_port = rule.from_port
    to_port = rule.to_port + 1
    LOG.debug("from_port=%s, to_port=%s", from_port, to_port)
    for port in range(from_port, to_port):
        c = dict(dst_cidr=dst_cidr, dst_port=port)
        if rule.protocol:
            c['protocol'] = rule.protocol
        if rule.cidr:
            c['src_cidr'] = rule.cidr
        f = dict(condition=c,
                 action='ACCEPT',
                 priority=priority )
        b = dict(filter=f)
        filter_bodys.append(b)
    LOG.debug("security_group_rule.id=%s -> %s", rule.id, filter_bodys)
    return filter_bodys


def _build_default_drop_filter(dst_cidr):
    filter_bodys = []
    for proto in [ "tcp", "udp", "icmp" ]:
        b = dict(filter=dict(condition=dict(dst_cidr=dst_cidr, protocol=proto),
                             action='DROP',
                             priority=DEFAULT_DROP_PRIORITY ))
        filter_bodys.append(b)
    b = dict(filter=dict(condition=dict(dst_cidr=dst_cidr),
                         action='ACCEPT',
                         priority=DEFAULT_ACCEPT_PRIORITY ))
    filter_bodys.append(b)
    return filter_bodys

def _create_filters(qfc, tenant_id, network_uuid, filter_bodys):
    filter_ids = []
    dup_ids = []
    for filter_body in filter_bodys:
        LOG.debug("creating filter %s/%s %s", tenant_id, network_uuid, filter_body)
        try:
            filter_id = qfc.create_filter(tenant_id, network_uuid, filter_body)
            # TODO if same filter already exists, add to dup_ids
            LOG.debug("created filter %s/%s/%s", tenant_id, network_uuid, filter_id)
            filter_ids.append(filter_id)
        except:
            LOG.exception("exception")
    return (filter_ids, dup_ids)


def _delete_filters(qfc, tenant_id, network_uuid, filter_ids):
    for filter_id in filter_ids:
        LOG.debug("deleting filter %s/%s/%s", tenant_id, network_uuid, filter_id)
        try:
            qfc.delete_filter(tenant_id, network_uuid, filter_id)
        except:
            LOG.exception("exception")


def _list_filters(qfc, tenant_id, network_uuid):
    LOG.debug("list filters %s/%s", tenant_id, network_uuid)
    try:
        return qfc.list_filters(tenant_id, network_uuid)
    except:
        LOG.exception("exception")


def _from_network_info(network, mapping, tenant_id):
    vif_uuid = mapping.get('vif_uuid')
    if not vif_uuid:
        LOG.debug("vif_uuid is None")
        return None
    ctxt = context.get_admin_context()
    vif_ref = db.virtual_interface_get_by_uuid(ctxt, vif_uuid)
    if not vif_ref:
        LOG.debug("vif_ref is None")
        return None
    network_ref = vif_ref.network
    if not network_ref:
        LOG.debug("network_ref is None")
        return None
    network_uuid = network_ref.uuid
    if not network_uuid:
        LOG.debug("network_uuid is None")
        return None
    vifinfo_uuid = _get_vifinfo_uuid(tenant_id, vif_uuid)
    if not vifinfo_uuid:
        LOG.debug("vifinfo_uuid is None")
        return None
    LOG.debug("ips = %s", mapping.get('ips', []))
    ips = []
    for i in mapping.get('ips', []):
        ips.append(i['ip'])
    return (vifinfo_uuid, network_uuid, ips)


class QuantumFilterFirewall(firewall.FirewallDriver):

    # self._network_infos = { instance_id: network_info }
    # self._basic_filters = { instance_id: { network_uuid: [filter_id] } }
    # self._filters = { instance_id: { network_uuid: [filter_id] } }
    
    def __init__(self):
        LOG.debug("QFC = %s", FLAGS.physical_quantum_filter_connection)
        QFC = utils.import_class(FLAGS.physical_quantum_filter_connection)
        self._connection = QFC()
        self._network_infos = {}
        self._basic_filters = {}
        self._filters = {}

    def prepare_instance_filter(self, instance, network_info):
        """Prepare filters for the instance.
        At this point, the instance isn't running yet."""
        LOG.debug("prepare_instance_filter: %s", locals())
        tenant_id = instance['project_id']
        ctxt = context.get_admin_context()
        new_filters = {}
        not_to_delete = {}
        for (network,mapping) in network_info:
            LOG.debug("handling network=%s mapping=%s", network, mapping)
            info = _from_network_info(network, mapping, tenant_id)
            if not info:
                LOG.debug("skip this network_info")
                continue
            vifinfo_uuid,network_uuid,ips = info
            filter_bodys = []
            for ip in ips:
                dd_f = _build_default_drop_filter(ip + "/32")
                filter_bodys.extend(dd_f)
                for sg in instance.security_groups:
                    LOG.debug("security_group.id=%s", sg.id)
                    rules = db.security_group_rule_get_by_security_group(ctxt, sg.id)
                    for rule in rules:
                        rule_f = _build_security_group_rule_filter(ip + "/32", rule, SECURITY_GROUP_PRIORITY)
                        filter_bodys.extend(rule_f)
            # TODO add duplicated id to list
            ids,dup_ids = _create_filters(self._connection, tenant_id, network_uuid, filter_bodys)
            new_filters[network_uuid] = ids
            not_to_delete[network_uuid] = dup_ids
        LOG.debug("new_filters = %s", new_filters)

        # delete old filters
        for (network_uuid,filter_ids) in self._filters.get(instance.id, {}).iteritems():
            fid_dict = {}
            for fid in filter_ids:
                fid_dict[fid] = None
            for excl_fid in not_to_delete[network_uuid]:
                del(fid_dict[excl_fid])
            _delete_filters(self._connection, tenant_id, network_uuid, fid_dict.keys())

        self._filters[instance.id] = new_filters
        self._network_infos[instance.id] = network_info
        LOG.debug("prepare_instance_filter: end")

    def unfilter_instance(self, instance, network_info):
        """Stop filtering instance"""
        LOG.debug("unfilter_instance: %s", locals())
        tenant_id = instance['project_id']
        LOG.debug("filters: %s", self._filters)
        filters = self._filters.pop(instance.id, {})
        for (network_uuid,filter_ids) in self._filters.pop(instance.id, {}).iteritems():
            _delete_filters(self._connection, tenant_id, network_uuid, filter_ids)
        for (network_uuid,filter_ids) in self._basic_filters.pop(instance.id, {}).iteritems():
            _delete_filters(self._connection, tenant_id, network_uuid, filter_ids)
        self._network_infos.pop(instance.id, {})
        LOG.debug("unfilter_instance: end")

    def apply_instance_filter(self, instance, network_info):
        """Apply instance filter.

        Once this method returns, the instance should be firewalled
        appropriately. This method should as far as possible be a
        no-op. It's vastly preferred to get everything set up in
        prepare_instance_filter.
        """
        pass

    def refresh_security_group_rules(self, security_group_id):
        """Refresh security group rules from data store

        Gets called when a rule has been added to or removed from
        the security group."""
        LOG.debug("refresh_security_group_rules: %s", locals())
        ctxt = context.get_admin_context()
        sg = db.security_group_get(ctxt, security_group_id)
        for member in sg.instances:
            if self._filters.has_key(member.id):
                network_info = self._network_infos.get(member.id)
                self.prepare_instance_filter(member, network_info)
        LOG.debug("refresh_security_group_rules: end")

    def refresh_security_group_members(self, security_group_id):
        """Refresh security group members from data store

        Gets called when an instance gets added to or removed from
        the security group."""
        LOG.debug("refresh_security_group_members: %s", locals())
        LOG.warn("refresh_security_group_members: currently not implemented!")
        LOG.debug("refresh_security_group_members: end")

    def refresh_provider_fw_rules(self):
        """Refresh common rules for all hosts/instances from data store.

        Gets called when a rule has been added to or removed from
        the list of rules (via admin api).

        """
        LOG.debug("refresh_provider_fw_rules: %s", locals())
        LOG.debug("refresh_provider_fw_rules: end")

    def setup_basic_filtering(self, instance, network_info):
        """Create rules to block spoofing and allow dhcp.

        This gets called when spawning an instance, before
        :method:`prepare_instance_filter`.

        """
        LOG.debug("setup_basic_filtering: %s", locals())
        tenant_id = instance['project_id']
        new_basic_filters = {}
        for (network,mapping) in network_info:
            filter_bodys = []
            LOG.debug("handling network=%s mapping=%s", network, mapping)
            info = _from_network_info(network, mapping, tenant_id)
            if not info:
                LOG.debug("skip this network_info")
                continue
            vifinfo_uuid,network_uuid,ips = info
            mac = mapping.get('mac')
            LOG.debug("mac=%s", mac)

            f = _build_deny_dhcp_server(vifinfo_uuid)
            LOG.debug("deny_dhcp_servers: %s", f)
            filter_bodys.extend(f)

            f = _build_allow_dhcp_client(vifinfo_uuid, mac)
            LOG.debug("allow_dhcp_client: %s", f)
            filter_bodys.extend(f)

            for ip in ips:
                f = _build_allow_src(vifinfo_uuid, mac, ip + '/32')
                LOG.debug("allow_src: %s", f)
                filter_bodys.extend(f)

            f = _build_deny_all(vifinfo_uuid)
            LOG.debug("deny_all: %s", f)
            filter_bodys.extend(f)

            ids,dup_ids = _create_filters(self._connection, tenant_id, network_uuid, filter_bodys)
            new_basic_filters[network_uuid] = ids

        self._network_infos[instance.id] = network_info
        self._basic_filters[instance.id] = new_basic_filters
        LOG.debug("setup_basic_filtering: end")

    def instance_filter_exists(self, instance, network_info):
        """Check nova-instance-instance-xxx exists"""
        return self._filters.has_key(instance.id)

""" end add by NTT DOCOMO """