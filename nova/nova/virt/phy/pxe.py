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

from nova import flags
from nova import log as logging
from nova import utils


LOG = logging.getLogger("phy.pxe")


FLAGS = flags.FLAGS

def get_baremetal_nodes():
    return PXE()

from nova.virt.phy import vlan 
from nova import exception
from nova import log as logging
from nova.openstack.common import cfg
from nova import utils
from nova import flags
from nova import context as nova_context
from nova import db
from nova.virt.baremetal import bmdb
from nova.compute import power_state
from nova.compute import instance_types
from nova.virt import driver
from nova.virt import images
from nova.virt.disk import api as disk
from nova.virt.libvirt import utils as libvirt_utils

from nova.virt.phy.nec_firewall2 import QuantumFilterFirewall
from nova.virt.phy.nec_firewall2 import DisabledQuantumFilterFirewall
from nova.virt.phy import physical_states

import os
import shutil

Template = None
def _late_load_cheetah():
    global Template
    if Template is None:
        t = __import__('Cheetah.Template', globals(), locals(),
                       ['Template'], -1)
        Template = t.Template

def _console_pidfile(host_id):
    pidfile = "%s/%s.pid" % (FLAGS.physical_console_pid_dir,host_id)
    return pidfile

def _console_pid(host_id):
    pidfile = _console_pidfile(host_id)
    if os.path.exists(pidfile):
        with open(pidfile, 'r') as f:
            return int(f.read())
    return None

def _dnsmasq_pid_path(pxe_interface):
    name = 'dnsmasq-%s.pid' % pxe_interface
    path = os.path.join(FLAGS.physical_dnsmasq_pid_dir, name)
    return path

def _dnsmasq_lease_path(pxe_interface):
    name = 'dnsmasq-%s.lease' % pxe_interface
    path = os.path.join(FLAGS.physical_dnsmasq_lease_dir, name)
    return path

def _dnsmasq_pid(pxe_interface):
    pidfile = _dnsmasq_pid_path(pxe_interface)
    if os.path.exists(pidfile):
        with open(pidfile, 'r') as f:
            return int(f.read())
    return None

def _ensure_directory(path):
    try:
        os.makedirs(path)
    except:
        pass
    if not os.path.isdir(path):
        raise exception.Error

def _unlink_without_raise(path):
    try:
        os.unlink(path)
    except OSError:
        LOG.exception("failed to unlink %s" % path)

def _random_alnum(count):
    import random
    import string
    chars = string.ascii_uppercase + string.digits
    return "".join([ random.choice(chars) for i in range(count) ])


class PXE:

    def __init__(self):
        if FLAGS.physical_enable_firewall:
            self._firewall_driver = QuantumFilterFirewall()
        else:
            self._firewall_driver = DisabledQuantumFilterFirewall()

    def define_vars(self, instance, network_info, block_device_info):
        var = {}
        var['instance'] = instance
        var['image_root'] = os.path.join(FLAGS.instances_path, instance['name'])
        if FLAGS.physical_pxe_vlan_per_host:
            var['tftp_root'] = os.path.join(FLAGS.physical_tftp_root, str(instance['id']))
            var['tftp_root_create'] = True
            var['tftp_root_remove'] = True
        else:
            var['tftp_root'] = FLAGS.physical_tftp_root
            var['tftp_root_create'] = False
            var['tftp_root_remove'] = False
        var['network_info'] = network_info
        var['block_device_info'] = block_device_info
        return var
    
    def _start_pxe_server(self, var, context, host):
        tftp_root = var['tftp_root']
        if FLAGS.physical_pxe_vlan_per_host:
            parent_interface = FLAGS.physical_pxe_parent_interface
            pxe_ip_id = bmdb.phy_pxe_ip_associate(context, host.id)
            pxe_ip = bmdb.phy_pxe_ip_get(context, pxe_ip_id)
            vlan_num = host.pxe_vlan_id
            server_address = pxe_ip.server_address
            client_address = pxe_ip.address

            ### care care care moving for pxe.py ###
            pxe_interface = vlan.ensure_vlan(vlan_num, parent_interface)

            from nova.network import linux_net
            
            chain = 'phy-%s' % pxe_interface
            iptables = linux_net.iptables_manager
            iptables.ipv4['filter'].add_chain(chain)
            iptables.ipv4['filter'].add_rule('INPUT', '-i %s -j $%s' % (pxe_interface, chain))
            iptables.ipv4['filter'].add_rule(chain, '--proto udp --sport=68 --dport=67 -j ACCEPT')
            iptables.ipv4['filter'].add_rule(chain, '-s %s -j ACCEPT' % client_address)
            iptables.ipv4['filter'].add_rule(chain, '-j DROP')
            iptables.apply()

            utils.execute('ip', 'address',
                    'add', server_address + '/24',
                    'dev', pxe_interface,
                    run_as_root=True)
            utils.execute('ip', 'route', 'add',
                    client_address, 'scope', 'host', 'dev', pxe_interface,
                    run_as_root=True)

            shutil.copyfile(FLAGS.physical_pxelinux_path, os.path.join(tftp_root, 'pxelinux.0'))
            _ensure_directory(os.path.join(tftp_root, 'pxelinux.cfg'))

            _start_pxe_server(interface=pxe_interface,
                                 tftp_root=tftp_root,
                                 client_address=client_address,
                                 pid_path=_dnsmasq_pid_path(pxe_interface),
                                 lease_path=_dnsmasq_lease_path(pxe_interface))

    def _stop_pxe_service(self, var, context, host):
        tftp_root = var['tftp_root']

        if FLAGS.physical_pxe_vlan_per_host:
            vlan_num = host.pxe_vlan_id
            pxe_interface = 'vlan%d' % vlan_num
            
            dnsmasq_pid = _dnsmasq_pid(pxe_interface)
            if dnsmasq_pid:
                utils.execute(FLAGS.physical_kill_dnsmasq_path, str(dnsmasq_pid), run_as_root=True)
            _unlink_without_raise(_dnsmasq_pid_path(pxe_interface))
            _unlink_without_raise(_dnsmasq_lease_path(pxe_interface))                
            
            utils.execute('ip', 'link', 'set', pxe_interface, 'down', run_as_root=True)
            utils.execute('vconfig', 'rem', pxe_interface, run_as_root=True)
            
            shutil.rmtree(os.path.join(tftp_root, 'pxelinux.cfg'), ignore_errors=True)

            from nova.network import linux_net
            chain = 'phy-%s' % pxe_interface
            iptables = linux_net.iptables_manager
            iptables.ipv4['filter'].remove_chain(chain)
            iptables.apply()            

            bmdb.phy_pxe_ip_disassociate(context, host.id)

    def init_host_nic(self, var, context, host):
        pifs = bmdb.phy_interface_get_all_by_phy_host_id(context, host['id'])
        for pif in pifs:
            if pif.vif_uuid:
                bmdb.phy_interface_set_vif_uuid(context, pif.id, None)

    def start_firewall(self, var):
        instance = var['instance']
        network_info = var['network_info']

        self._firewall_driver.setup_basic_filtering(instance, network_info)
        self._firewall_driver.update_instance_filter(instance, network_info)

    def stop_firewall(self, var):
        instance = var['instance']
        network_info = var['network_info']

        self._firewall_driver.unfilter_instance(instance,
                                                network_info=network_info)

    def _fetch_image(self, context, target, image_id, user_id, project_id):
        """Grab image and optionally attempt to resize it"""
        images.fetch_to_raw(context, image_id, target, user_id, project_id)

    def _cache_image_x(self, context, target, image_id, user_id, project_id):
        """Grab image and optionally attempt to resize it"""
        if not os.path.exists(target):
            self._fetch_image(context, target, image_id, user_id, project_id)

    def _inject_to_image(self, target, inst, network_info, nics_in_order):
        # For now, we assume that if we're not using a kernel, we're using a
        # partitioned disk image where the target partition is the first
        # partition
        target_partition = None
        if not inst['kernel_id']:
            target_partition = "1"

        # rename nics to be in order
        LOG.debug("injecting persisitent net")
        rules = ""
        i = 0
        for hwaddr in nics_in_order:
           rules += 'SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="%s", ATTR{dev_id}=="0x0", ATTR{type}=="1", KERNEL=="eth*", NAME="eth%d"\n' % (hwaddr.lower(),i)
           i += 1
        disk.inject_files(target,
                          [ ('/etc/udev/rules.d/70-persistent-net.rules', rules) ],
                          partition=target_partition,
                          use_cow=False)
        bootif_name = "eth%d" % (i-1)

        if inst['key_data']:
            key = str(inst['key_data'])
        else:
            key = None
        net = ""
        nets = []
        ifc_template = open(FLAGS.injected_network_template).read()
        ifc_num = -1
        have_injected_networks = False
        for (network_ref, mapping) in network_info:
            ifc_num += 1
            # always inject
            #if not network_ref['injected']:
            #    continue
            have_injected_networks = True
            address = mapping['ips'][0]['ip']
            netmask = mapping['ips'][0]['netmask']
            address_v6 = None
            gateway_v6 = None
            netmask_v6 = None
            if FLAGS.use_ipv6:
                address_v6 = mapping['ip6s'][0]['ip']
                netmask_v6 = mapping['ip6s'][0]['netmask']
                gateway_v6 = mapping['gateway_v6']
            name = 'eth%d' % ifc_num
            if FLAGS.physical_use_unsafe_vlan and mapping['should_create_vlan'] and network_ref.get('vlan'):
                name = 'eth%d.%d' % (ifc_num,network_ref.get('vlan'))
            net_info = {'name': name,
                   'address': address,
                   'netmask': netmask,
                   'gateway': mapping['gateway'],
                   'broadcast': mapping['broadcast'],
                   'dns': ' '.join(mapping['dns']),
                   'address_v6': address_v6,
                   'gateway_v6': gateway_v6,
                   'netmask_v6': netmask_v6,
                   'hwaddress': mapping['mac']}
            nets.append(net_info)

        if have_injected_networks:
            _late_load_cheetah()
            net = str(Template(ifc_template,
                               searchList=[{'interfaces': nets,
                                            'use_ipv6': FLAGS.use_ipv6}]))
        net += "\n"
        net += "auto %s\n" % bootif_name
        net += "iface %s inet dhcp\n" % bootif_name

        if FLAGS.physical_inject_password:
            admin_password = inst.get('admin_pass')
        else:
            admin_password = None

        metadata = inst.get('metadata')
        if any((key, net, metadata, admin_password)):
            inst_name = inst['name']

            img_id = inst.image_ref

            for injection in ('metadata', 'key', 'net', 'admin_password'):
                if locals()[injection]:
                    LOG.info(_('instance %(inst_name)s: injecting '
                               '%(injection)s into image %(img_id)s'),
                             locals(), instance=inst)
            try:
                disk.inject_data(target,
                                 key, net, metadata, admin_password,
                                 partition=target_partition,
                                 use_cow=False)

            except Exception as e:
                # This could be a windows image, or a vmdk format disk
                LOG.warn(_('instance %(inst_name)s: ignoring error injecting'
                        ' data into image %(img_id)s (%(e)s)') % locals(),
                         instance=inst)

    def create_image(self, var, context, image_meta, host):
        instance = var['instance']
        image_root = var['image_root']
        tftp_root = var['tftp_root']
        tftp_root_create = var['tftp_root_create']
        network_info = var['network_info']

        nics_in_order = []
        pifs = bmdb.phy_interface_get_all_by_phy_host_id(context, host['id'])
        for pif in pifs:
            nics_in_order.append(pif['address'])
        nics_in_order.append(host['pxe_mac_address'])
        var['nics_in_order'] = nics_in_order
        
        ami_id = str(image_meta['id'])
        aki_id = str(instance['kernel_id'])
        ari_id = str(instance['ramdisk_id'])
        deploy_aki_id = FLAGS.physical_deploy_kernel
        deploy_ari_id = FLAGS.physical_deploy_ramdisk

        image_target = os.path.join(image_root, ami_id)

        kernel_target = os.path.join(tftp_root, aki_id)
        ramdisk_target = os.path.join(tftp_root, ari_id)
        deploy_kernel_target = os.path.join(tftp_root, deploy_aki_id)
        deploy_ramdisk_target = os.path.join(tftp_root, deploy_ari_id)

        _ensure_directory(image_root)
        if tftp_root_create:
            _ensure_directory(tftp_root)

        LOG.debug("fetching image id=%s target=%s", ami_id, image_target)
        
        ### care care care moving for pxe.py ###
        self._cache_image_x(context=context,
                            target=image_target,
                            image_id=ami_id,
                            user_id=instance['user_id'],
                            project_id=instance['project_id'])
        LOG.debug("injecting to image id=%s target=%s", ami_id, image_target)
        self._inject_to_image(image_target, instance, network_info, nics_in_order)

        LOG.debug("fetching kernel id=%s target=%s", aki_id, kernel_target)
        self._cache_image_x(context=context,
                          image_id=aki_id,
                          target=kernel_target,
                          user_id=instance['user_id'],
                          project_id=instance['project_id'])

        LOG.debug("fetching ramdisk id=%s target=%s", ari_id, ramdisk_target)
        self._cache_image_x(context=context,
                          image_id=ari_id,
                          target=ramdisk_target,
                          user_id=instance['user_id'],
                          project_id=instance['project_id'])

        LOG.debug("fetching deploy_kernel id=%s target=%s", deploy_aki_id, deploy_kernel_target)
        self._cache_image_x(context=context,
                          image_id=deploy_aki_id,
                          target=deploy_kernel_target,
                          user_id=instance['user_id'],
                          project_id=instance['project_id'])

        LOG.debug("fetching deploy_ramdisk id=%s target=%s", deploy_ari_id, deploy_ramdisk_target)
        self._cache_image_x(context=context,
                          image_id=deploy_ari_id,
                          target=deploy_ramdisk_target,
                          user_id=instance['user_id'],
                          project_id=instance['project_id'])
        
        var['image_target'] = image_target
        var['aki_id'] = aki_id
        var['ari_id'] = ari_id

        LOG.debug("fetching images all done")

    def destroy_images(self, var):
        image_root = var['image_root']
        tftp_root = var['tftp_root']
        tftp_root_remove = var['tftp_root_remove']

        shutil.rmtree(image_root, ignore_errors=True)
        if tftp_root_remove:
            shutil.rmtree(tftp_root, ignore_errors=True)

    def activate_bootloader(self, var, context, host):
        #start moving to create_domain in XXX.py ###
        self._create_pxe_config(var, context, host)
        #start moving to create_domain in XXX.py ###
        self._start_pxe_server(var, context, host)
        #end moving to create_domain in XXX.py ###

    def deactivate_bootloader(self, var, context, host):
        self._stop_pxe_service(var, context, host)
        self._remove_pxe_config(var, context, host)
        
    def _create_pxe_config(self, var, context, host):
        tftp_root = var['tftp_root']
        instance = var['instance']
        image_target = var['image_target']
        aki_id = var['aki_id']
        ari_id = var['ari_id']

        pxe_config_dir = os.path.join(tftp_root, 'pxelinux.cfg')
        pxe_config_path = os.path.join(pxe_config_dir, "01-" + host.pxe_mac_address.replace(":", "-").lower())

        root_mb = instance['root_gb'] * 1024

        inst_type_id = instance['instance_type_id']
        inst_type = instance_types.get_instance_type(inst_type_id)
        swap_mb = inst_type['swap']
        if swap_mb < 1024:
            swap_mb = 1024

        ### care care care moving for pxe.py ###
        deployment_key = _random_alnum(32)
        deployment_id = bmdb.phy_deployment_create(context, deployment_key, image_target, pxe_config_path, root_mb, swap_mb)

        # 'default deploy' will be replaced to 'default boot' by phy_deploy_work
        pxeconf = "default deploy\n"
        pxeconf += "\n"

        pxeconf += "label deploy\n"
        pxeconf += "kernel %s\n" % FLAGS.physical_deploy_kernel
        pxeconf += "append"
        pxeconf += " initrd=%s" % FLAGS.physical_deploy_ramdisk
        pxeconf += " selinux=0"
        pxeconf += " disk=cciss/c0d0,sda,hda"
        pxeconf += " iscsi_target_iqn=iqn-%s" % str(instance['uuid'])
        pxeconf += " deployment_id=%s" % deployment_id
        pxeconf += " deployment_key=%s" % deployment_key
        pxeconf += "\n"
        pxeconf += "ipappend 3\n"
        pxeconf += "\n"

        pxeconf += "label boot\n"
        pxeconf += "kernel %s\n" % aki_id
        pxeconf += "append"
        pxeconf += " initrd=%s" % ari_id
        # ${ROOT} will be replaced to UUID=... by phy_deploy_work
        pxeconf += " root=${ROOT} ro"
        pxeconf += "\n"
        pxeconf += "\n"

        _ensure_directory(pxe_config_dir)

        f = open(pxe_config_path, 'w')
        f.write(pxeconf)
        f.close()

    def _remove_pxe_config(self, var, context, host):
        tftp_root = var['tftp_root']
        pxe_config_path = os.path.join(tftp_root, "pxelinux.cfg", "01-" + host.pxe_mac_address.replace(":", "-").lower())
        _unlink_without_raise(pxe_config_path)

    def attach_volumes_on_spawn(self, var):
        instance = var['instance']
        block_device_info = var['block_device_info']
        ## placeholder
        pass
    
    def detach_volumes_on_destroy(self, var):
        instance = var['instance']
        block_device_info = var['block_device_info']

        # NOTE(vish): we disconnect from volumes regardless
        block_device_mapping = driver.block_device_info_get_mapping(
            block_device_info)
        for vol in block_device_mapping:
            connection_info = vol['connection_info']
            mountpoint = vol['mount_device']
            self.detach_volume(connection_info, instance['name'], mountpoint)

def _start_pxe_server(interface, tftp_root, client_address, pid_path, lease_path):
    utils.execute('dnsmasq',
             '--conf-file=',
             '--pid-file=%s' % pid_path,
             '--dhcp-leasefile=%s' % lease_path,
             '--port=0',
             '--bind-interfaces',
             '--interface=%s' % interface,
             '--enable-tftp',
             '--tftp-root=%s' % tftp_root,
             '--dhcp-boot=pxelinux.0',
             '--dhcp-range=%s,%s' % (client_address,client_address))


""" end add by NTT DOCOMO """
