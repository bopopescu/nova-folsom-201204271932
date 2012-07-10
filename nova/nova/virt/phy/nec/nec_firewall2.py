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

""" start mod by NTT DOCOMO """

from webob import exc
import pprint

from nova import context
from nova import db
from nova.virt.baremetal import bmdb
from nova import flags
from nova import log as logging
from nova import utils
from nova.virt import firewall

from nec_firewall import _get_vifinfo_uuid
from nec_firewall import _build_deny_dhcp_server
from nec_firewall import _build_allow_dhcp_client
from nec_firewall import _build_security_group_rule_filter
from nec_firewall import _create_filters
from nec_firewall import _list_filters
from nec_firewall import _delete_filters


LOG = logging.getLogger(__name__)
FLAGS = flags.FLAGS

INTERNAL_SECURITY_GROUP_PRIORITY = 10020
INTERNAL_ALLOW_ARP_PRIORITY      = 10015
INTERNAL_DROP_ALL_PRIORITY       = 10011

EXTERNAL_SECURITY_GROUP_PRIORITY = 10010
EXTERNAL_ALLOW_ARP_PRIORITY      = 10005
EXTERNAL_DROP_ALL_PRIORITY       = 10000


def _pp(obj):
    pp = pprint.PrettyPrinter()
    return pp.pformat(obj)

def _in_cidr(addr, cidr):
    c_addr,c_len = cidr.split("/", 3)
    c_len = int(c_len)
    c_octs = c_addr.split(".", 5)
    if len(c_octs) != 4:
        return False
    octs = addr.split(".", 5)
    if (len(octs) != 4):
        return False
    c_bits = 0
    a_bits = 0
    for o in c_octs:
        c_bits <<= 8
        c_bits |= int(o)
    for o in octs:
        a_bits <<= 8
        a_bits |= int(o)
    c_bits >>= 32 - c_len
    a_bits >>= 32 - c_len
    return c_bits == a_bits


def _build_default_drop_filter(dst_cidr):
    filter_bodys = []
    b = dict(filter=dict(condition=dict(dst_cidr=dst_cidr, protocol='arp'),
                         action='ACCEPT',
                         priority=EXTERNAL_ALLOW_ARP_PRIORITY ))
    filter_bodys.append(b)
    b = dict(filter=dict(condition=dict(dst_cidr=dst_cidr),
                         action='DROP',
                         priority=EXTERNAL_DROP_ALL_PRIORITY ))
    filter_bodys.append(b)
    return filter_bodys


def _from_phy_host(instance_id, tenant_id):
    LOG.debug('_from_phy_host(instance_id=%s,tenant_id=%s)', instance_id, tenant_id)
    ctx = context.get_admin_context()
    info = []
    for vif in db.virtual_interface_get_by_instance(ctx, instance_id):
        LOG.debug('vif=%s', vif.__dict__)
        mac = vif.address
        network_ref = vif.network
        if not network_ref:
            LOG.warn('vif.network is None')
            continue
        LOG.debug('vif.network=%s', network_ref.__dict__)
        network_uuid = network_ref.uuid
        if not network_uuid:
            LOG.warn('network_uuid is None')
            continue
        vifinfo_uuid = _get_vifinfo_uuid(tenant_id, vif.uuid)
        LOG.debug('vifinfo_uuid=%s', vifinfo_uuid)
        if not vifinfo_uuid:
            continue
        fixed_ips = db.fixed_ips_by_virtual_interface(ctx, vif.id)
        if not fixed_ips:
            LOG.warn('fixed_ip is None')
            continue
        addrs = [ fip.address for fip in fixed_ips ]
        info.append( (vifinfo_uuid, network_uuid, mac, addrs) )
    LOG.debug('_from_phy_host(instance_id=%s,tenant_id=%s) end: info=%s', instance_id, tenant_id, info)
    return info


def _build_full_security_group_rule_filter(in_port, src_mac, src_cidr, dst_cidr, rule):
    filter_bodys = []
    from_port = rule.from_port
    to_port = rule.to_port + 1
    LOG.debug("from_port=%s, to_port=%s", from_port, to_port)
    for port in range(from_port, to_port):
        c = dict(in_port=in_port,
                 src_mac=src_mac,
                 src_cidr=src_cidr,
                 dst_cidr=dst_cidr,
                 dst_port=port)
        if rule.protocol:
            c['protocol'] = rule.protocol
        f = dict(condition=c,
                 action='ACCEPT',
                 priority=INTERNAL_SECURITY_GROUP_PRIORITY )
        b = dict(filter=f)
        filter_bodys.append(b)
    LOG.debug("security_group_rule.id=%s -> %s", rule.id, filter_bodys)
    return filter_bodys


def _build_full_default_drop_filter(in_port, src_mac, src_cidr, dst_cidr):
    filter_bodys = []
    b = dict(filter=dict(condition=dict(in_port=in_port,
                                        src_mac=src_mac,
                                        src_cidr=src_cidr,
                                        dst_cidr=dst_cidr,
                                        protocol="arp"),
                         action='ACCEPT',
                         priority=INTERNAL_ALLOW_ARP_PRIORITY ))
    filter_bodys.append(b)

    b = dict(filter=dict(condition=dict(in_port=in_port,
                                        #dl_src=src_mac,
                                        #src_cidr=src_cidr,
                                        dst_cidr=dst_cidr),
                         action='DROP',
                         priority=INTERNAL_DROP_ALL_PRIORITY ))
    filter_bodys.append(b)
    return filter_bodys
    

def _fullbuild(conn):
    tenants_networks_filters = {}
    
    def _extend(tenant_id, network_id, filter_bodys):
        if not tenants_networks_filters.has_key(tenant_id):
            tenants_networks_filters[tenant_id] = {}
        if not tenants_networks_filters[tenant_id].has_key(network_id):
            tenants_networks_filters[tenant_id][network_id] = []
        tenants_networks_filters[tenant_id][network_id].extend(filter_bodys)
    
    ctxt = context.get_admin_context()
    hosts = bmdb.phy_host_get_all(ctxt)
    for t in hosts:
        LOG.debug('to.id=%s', t.id)
        LOG.debug('to=%s', t.__dict__)
        if not t.instance_id:
            continue
        ti = db.instance_get(ctxt, t.instance_id)
        LOG.debug('to.instance=%s', ti.__dict__)
        
        # DHCP from the instance
        for (in_port,network_uuid,mac,_) in _from_phy_host(ti.id, ti.project_id):
            filter_bodys = []
            filter_bodys.extend(_build_allow_dhcp_client(in_port, mac))
            filter_bodys.extend(_build_deny_dhcp_server(in_port))
            _extend(ti.project_id, network_uuid, filter_bodys)

        # from external host to the instance
        LOG.debug('from=* to.id=%s', t.id)
        for (_,network_uuid,_,t_ips) in _from_phy_host(ti.id, ti.project_id):
            filter_bodys = []
            for t_ip in t_ips:
                for sg in db.security_group_get_by_instance(ctxt, ti.id):
                    rules = db.security_group_rule_get_by_security_group(ctxt, sg.id)
                    for rule in rules:
                        rule_f = _build_security_group_rule_filter(t_ip + "/32", rule, EXTERNAL_SECURITY_GROUP_PRIORITY)
                        filter_bodys.extend(rule_f)
                rule_f = _build_default_drop_filter(t_ip + "/32")
                filter_bodys.extend(rule_f)
            _extend(ti.project_id, network_uuid, filter_bodys)

        # from other instances to the instance
        for f in hosts:
            LOG.debug('from.id=%s to.id=%s', f.id, t.id)
            if f.id == t.id:
                continue
            if not f.instance_id:
                continue
            fi = db.instance_get(ctxt, f.instance_id)
            LOG.debug('from.instance=%s', fi.__dict__)
            for (in_port,network_uuid,mac,f_ips) in _from_phy_host(fi.id, fi.project_id):
                filter_bodys = []
                for (_,_,_,t_ips) in _from_phy_host(ti.id, ti.project_id):
                    for f_ip in f_ips:
                        for t_ip in t_ips:
                            for sg in db.security_group_get_by_instance(ctxt, ti.id):
                                rules = db.security_group_rule_get_by_security_group(ctxt, sg.id)
                                for rule in rules:
                                    if rule.cidr and not _in_cidr(f_ip, rule.cidr):
                                        continue
                                    rule_f = _build_full_security_group_rule_filter(in_port, mac, f_ip + "/32",
                                                                                    t_ip + "/32", rule)
                                    filter_bodys.extend(rule_f)
                            rule_f = _build_full_default_drop_filter(in_port, mac, f_ip + "/32", t_ip + "/32")
                            filter_bodys.extend(rule_f)
                _extend(fi.project_id, network_uuid, filter_bodys)

    LOG.debug('begin update filters')
    for (tenant_id, nf) in tenants_networks_filters.iteritems():
        for (network_id, filter_bodys) in nf.iteritems():
            old_fids = _list_filters(conn, tenant_id, network_id)
            LOG.debug("delete filters tenant_id=%s network_id=%s ids=\n%s", tenant_id, network_id, _pp(old_fids))
            _delete_filters(conn, tenant_id, network_id, old_fids)
            LOG.debug("create filters tenant_id=%s network_id=%s bodys=\n%s", tenant_id, network_id, _pp(filter_bodys))
            _create_filters(conn, tenant_id, network_id, filter_bodys)
    LOG.debug('end update filters')


def _delete_all(conn):
    pass


class QuantumFilterFirewall(firewall.FirewallDriver):

    # self._network_infos = { instance_id: network_info }
    # self._basic_filters = { instance_id: { network_uuid: [filter_id] } }
    # self._filters = { instance_id: { network_uuid: [filter_id] } }
    
    def __init__(self):
        LOG.debug("QFC = %s", FLAGS.physical_quantum_filter_connection)
        QFC = utils.import_class(FLAGS.physical_quantum_filter_connection)
        self._connection = QFC()

    def prepare_instance_filter(self, instance, network_info):
        """Prepare filters for the instance.
        At this point, the instance isn't running yet."""
        LOG.debug("prepare_instance_filter: %s", locals())
        _delete_all(self._connection)
        _fullbuild(self._connection);
        LOG.debug("prepare_instance_filter: end")

    def unfilter_instance(self, instance, network_info):
        """Stop filtering instance"""
        LOG.debug("unfilter_instance: %s", locals())
        _delete_all(self._connection)
        _fullbuild(self._connection);
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
        _delete_all(self._connection)
        _fullbuild(self._connection);
        LOG.debug("refresh_security_group_rules: end")

    def refresh_security_group_members(self, security_group_id):
        """Refresh security group members from data store

        Gets called when an instance gets added to or removed from
        the security group."""
        LOG.debug("refresh_security_group_members: %s", locals())
        _delete_all(self._connection)
        _fullbuild(self._connection);
        LOG.debug("refresh_security_group_members: end")

    def refresh_provider_fw_rules(self):
        """Refresh common rules for all hosts/instances from data store.

        Gets called when a rule has been added to or removed from
        the list of rules (via admin api).

        """
        LOG.debug("refresh_provider_fw_rules: %s", locals())
        _delete_all(self._connection)
        _fullbuild(self._connection);
        LOG.debug("refresh_provider_fw_rules: end")

    def setup_basic_filtering(self, instance, network_info):
        """Create rules to block spoofing and allow dhcp.

        This gets called when spawning an instance, before
        :method:`prepare_instance_filter`.

        """
        LOG.debug("setup_basic_filtering: %s", locals())
        LOG.debug("setup_basic_filtering: end")

    def instance_filter_exists(self, instance, network_info):
        """Check nova-instance-instance-xxx exists"""
        return self._filters.has_key(instance.id)

     
""" end mod by NTT DOCOMO """

