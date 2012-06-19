
# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

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

from nova import exception
from nova import log as logging
from nova.openstack.common import cfg
from nova import utils
from nova import flags
from nova import context as nova_context
from nova import db
from nova.compute import power_state
from nova.compute import instance_types
from nova.virt import driver
from nova.virt import images
from nova.virt.disk import api as disk

from nova.virt.phy.nec_firewall2 import QuantumFilterFirewall
from nova.virt.phy.nec_firewall2 import DisabledQuantumFilterFirewall
from nova.virt.phy import physical_states

import os
import shutil

from nova.virt.phy import ipmi

# for FLAGS.baremetal_type
from nova.virt.baremetal import proxy
import UserDict

physical_opts = [
    cfg.BoolOpt('physical_use_unsafe_vlan',
                default=False,
                help='use physical host\'s vconfig for network isolation'),
    cfg.BoolOpt('physical_use_unsafe_iscsi',
                 default=False,
                 help='If a phyhost/instance dose not have an fixed PXE IP address, '
                       'volumes for the instance are iSCSI-exported with globally opened ACL' ),
    cfg.StrOpt('physical_tftp_root',
               default='/tftpboot',
               help='Physical compute node\'s tftp root path'),
    cfg.StrOpt('physical_vif_driver',
               default='nova.virt.phy.vif_driver.PhyVIFDriver',
               help='The physical VIF driver to configure the VIFs.'),
    cfg.BoolOpt('physical_pxe_vlan_per_host',
                default=False),
    cfg.StrOpt('physical_pxe_parent_interface',
               default='eth0'),
    cfg.StrOpt('physical_pxelinux_path',
               default='/usr/lib/syslinux/pxelinux.0',
               help='path to pxelinux.0'),
    cfg.StrOpt('physical_dnsmasq_pid_dir',
               default='/var/lib/nova/phy/dnsmasq',
               help='path to directory stores pidfiles of dnsmasq'),
    cfg.StrOpt('physical_dnsmasq_lease_dir',
               default='/var/lib/nova/phy/dnsmasq',
               help='path to directory stores leasefiles of dnsmasq'),
    cfg.StrOpt('physical_console',
               default='/nova-2011.3/bin/phy_console',
               help='path to phy_console'),
    cfg.StrOpt('physical_console_pid_dir',
               default='/var/lib/nova/phy/console',
               help='path to directory stores pidfiles of phy_console'),
    cfg.BoolOpt('physical_enable_firewall',
                default=False),
    cfg.StrOpt('physical_kill_dnsmasq_path',
               default='phy_kill_dnsmasq',
               help='path to phy_kill_dnsmasq'),
    cfg.StrOpt('physical_deploy_kernel',
               help='kernel image ID used in deployment phase'),
    cfg.StrOpt('physical_deploy_ramdisk',
               help='ramdisk image ID used in deployment phase'),
    cfg.BoolOpt('physical_inject_password',
                default=True,
                help='physical inject password or not'),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(physical_opts)

LOG = logging.getLogger('nova.virt.physical')


import shlex
import subprocess
import types
from eventlet import greenthread

# the version of execute that checks exitcode even if it is zero 
def execute(*cmd, **kwargs):
    """Helper method to execute command with optional retry.

    If you add a run_as_root=True command, don't forget to add the
    corresponding filter to nova.rootwrap !

    :param cmd:                Passed to subprocess.Popen.
    :param process_input:      Send to opened process.
    :param check_exit_code:    Single bool, int, or list of allowed exit
                               codes.  Defaults to [0].  Raise
                               exception.ProcessExecutionError unless
                               program exits with one of these code.
    :param delay_on_retry:     True | False. Defaults to True. If set to
                               True, wait a short amount of time
                               before retrying.
    :param attempts:           How many times to retry cmd.
    :param run_as_root:        True | False. Defaults to False. If set to True,
                               the command is prefixed by the command specified
                               in the root_helper FLAG.

    :raises exception.Error: on receiving unknown arguments
    :raises exception.ProcessExecutionError:

    :returns: a tuple, (stdout, stderr) from the spawned process, or None if
             the command fails.
    """

    process_input = kwargs.pop('process_input', None)
    check_exit_code = kwargs.pop('check_exit_code', [0])
    ignore_exit_code = False
    if isinstance(check_exit_code, bool):
        ignore_exit_code = not check_exit_code
        check_exit_code = [0]
    elif isinstance(check_exit_code, int):
        check_exit_code = [check_exit_code]
    delay_on_retry = kwargs.pop('delay_on_retry', True)
    attempts = kwargs.pop('attempts', 1)
    run_as_root = kwargs.pop('run_as_root', False)
    shell = kwargs.pop('shell', False)

    if len(kwargs):
        raise exception.Error(_('Got unknown keyword args '
                                'to utils.execute: %r') % kwargs)

    if run_as_root:
        cmd = shlex.split(FLAGS.root_helper) + list(cmd)
    cmd = map(str, cmd)

    while attempts > 0:
        attempts -= 1
        try:
            LOG.debug(_('Running cmd (subprocess): %s'), ' '.join(cmd))
            _PIPE = subprocess.PIPE  # pylint: disable=E1101
            obj = subprocess.Popen(cmd,
                                   stdin=_PIPE,
                                   stdout=_PIPE,
                                   stderr=_PIPE,
                                   close_fds=True,
                                   shell=shell)
            result = None
            if process_input is not None:
                result = obj.communicate(process_input)
            else:
                result = obj.communicate()
            obj.stdin.close()  # pylint: disable=E1101
            _returncode = obj.returncode  # pylint: disable=E1101
            #if _returncode:
            if _returncode is not None:
                LOG.debug(_('Result was %s') % _returncode)
                if not ignore_exit_code and _returncode not in check_exit_code:
                    (stdout, stderr) = result
                    raise exception.ProcessExecutionError(
                            exit_code=_returncode,
                            stdout=stdout,
                            stderr=stderr,
                            cmd=' '.join(cmd))
            return result
        except exception.ProcessExecutionError:
            if not attempts:
                raise
            else:
                LOG.debug(_('%r failed. Retrying.'), cmd)
                if delay_on_retry:
                    greenthread.sleep(random.randint(20, 200) / 100.0)
        finally:
            # NOTE(termie): this appears to be necessary to let the subprocess
            #               call clean something up in between calls, without
            #               it two execute calls in a row hangs the second one
            greenthread.sleep(0)


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


def _host_dhcp(mac, hostname, ip):
    return '%s,%s,%s' % (mac, hostname, ip)


Template = None
def _late_load_cheetah():
    global Template
    if Template is None:
        t = __import__('Cheetah.Template', globals(), locals(),
                       ['Template'], -1)
        Template = t.Template


def get_connection(_):
    return PhysicalConnection.instance()


def _random_alnum(count):
    import random
    import string
    chars = string.ascii_uppercase + string.digits
    return "".join([ random.choice(chars) for i in range(count) ])


def _build_ifcfg_from_mapping(device, mapping):
    hwaddr = mapping['mac']
    address = mapping['ips'][0]['ip']
    netmask = mapping['ips'][0]['netmask']
    gateway = mapping['gateway']

    n = ""
    n += "DEVICE=%s\n" % device
    n += "TYPE=Ethernet\n"
    n += "HWADDR=%s\n" % hwaddr
    n += "ONBOOT=yes\n"
    n += "IPADDR=%s\n" % address
    n += "NETMASK=%s\n" % netmask
    n += "GATEWAY=%s\n" % gateway
    return n

def _build_ifcfg_string_from_mapping(device, real_mac, mapping):
    virt_mac = mapping['mac']
    address = mapping['ips'][0]['ip']
    netmask = mapping['ips'][0]['netmask']
    gateway = mapping['gateway']

    return "%s,%s,%s,%s,%s,%s" % (device,real_mac,virt_mac,address,netmask,gateway)

def _unlink_without_raise(path):
    try:
        os.unlink(path)
    except OSError:
        LOG.exception("failed to unlink %s" % path)


def _get_ipmi(ipmi_address, ipmi_user, ipmi_password):
    if not ipmi_address:
        pm = ipmi.DummyIpmi()
    else:
        pm = ipmi.Ipmi(ipmi_address, ipmi_user, ipmi_password)
    return pm


import nova.virt.phy.vlan as vlan
import nova.virt.phy.pxe as pxe


class NoSuitablePhyHost(exception.NovaException):
    message = _("Failed to find suitable PhyHost")


class PhysicalConnection(driver.ComputeDriver):
    """Physical hypervisor driver"""

    def _get_dhcp_hosts(self, context):
        """Get network's hosts config in dhcp-host format."""
        hosts = []
        for ph in self._get_phy_hosts(context):
            ip = db.phy_pxe_ip_get_by_phy_host_id(context, ph.id)
            if ip:
                hosts.append(_host_dhcp(ph.pxe_mac_address, "phyhost-%s" % ph.id, ip.address))
        return '\n'.join(hosts)

    def __init__(self):
        LOG.info(_("Physical driver __init__"))
        if not FLAGS.physical_deploy_kernel:
            raise exception.NovaException('physical_deploy_kernel is not defined')
        if not FLAGS.physical_deploy_ramdisk:
            raise exception.NovaException('physical_deploy_ramdisk is not defined')
        self._vif_driver = utils.import_object(FLAGS.physical_vif_driver)
        if FLAGS.physical_enable_firewall:
            self._firewall_driver = QuantumFilterFirewall()
        else:
            self._firewall_driver = DisabledQuantumFilterFirewall()

    @classmethod
    def instance(cls):
        if not hasattr(cls, '_instance'):
            cls._instance = cls()
        return cls._instance

    def init_host(self, host):
        return

    def list_instances(self):
        l = []
        ctx = nova_context.get_admin_context()
        for i in self._get_phy_hosts(ctx):
            if i.instance:
                l.append(i.instance.name)
        return l

    def list_instances_detail(self):
        l = []
        ctx = nova_context.get_admin_context()
        for i in self._get_phy_hosts(ctx):
            if i.instance:
                pm = _get_ipmi(i.ipmi_address, i.ipmi_user, i.ipmi_password)
                ps = power_state.SHUTOFF
                if pm.is_power_on():
                    ps = power_state.RUNNING
                ii = driver.InstanceInfo(i.instance.name, ps)
                l.append(ii)
        return l

    def _get_phy_hosts(self, context):
        service = db.service_get_by_host_and_topic(context, FLAGS.host, "compute")
        if not service:
            LOG.warn("Could not get service_get_by_host_and_topic host=%s topic=%s", FLAGS.host, "compute")
            return []
        phy_hosts = db.phy_host_get_all(context)
        hosts = []
        for i in phy_hosts:
            if i.service_id == service.id:
                hosts.append(i)
        return hosts

    def _get_phy_host_by_instance_id(self, instance_id):
        ctx = nova_context.get_admin_context()
        for i in self._get_phy_hosts(ctx):
            if not i.instance:
                continue
            try:
                if i.instance.id == instance_id:
                    return i
            except exception.InstanceNotFound:
                continue
        return None
    
    def _get_phy_host_by_instance_name(self, instance_name):
        ctx = nova_context.get_admin_context()
        for i in self._get_phy_hosts(ctx):
            if not i.instance:
                continue
            try:
                if i.instance.name == instance_name:
                    return i
            except exception.InstanceNotFound:
                continue
        return None
    
    def _find_suitable_phy_host(self, context, instance):
        result = None
        for i in self._get_phy_hosts(context):
            if i.instance_id:
                continue
            if i.registration_status != 'done':
                continue
            if i.cpus < instance.vcpus:
                continue
            if i.memory_mb < instance.memory_mb:
                continue
            if result == None:
                result = i
            else:
                if i.cpus < result.cpus:
                    result = i
                elif i.cpus == result.cpus and i.memory_mb < result.memory_mb:
                    result = i

        return result            

    def spawn(self, context, instance, image_meta,
              network_info=None, block_device_info=None):
        LOG.debug("spawn:")
        LOG.debug("instance=%s", instance.__dict__)
        LOG.debug("image_meta=%s", image_meta)
        LOG.debug("network_info=%s", network_info)
        LOG.debug("block_device_info=%s", block_device_info)
        # TODO: handle block devices

        host = self._find_suitable_phy_host(context, instance)

        if not host:
            LOG.info("no suitable physical host found")
            raise NoSuitablePhyHost()

        db.phy_host_update(context, host['id'],
                           {'instance_id': instance['id'],
                            'task_state' : physical_states.BUILDING,
                            })

        nics_in_order = []
        pifs = db.phy_interface_get_all_by_phy_host_id(context, host['id'])
        for pif in pifs:
            nics_in_order.append(pif['address'])
            if pif.vif_uuid:
                db.phy_interface_set_vif_uuid(context, pif.id, None)
        nics_in_order.append(host['pxe_mac_address'])
        
        image_root = os.path.join(FLAGS.instances_path, instance['name'])
        tftp_root = FLAGS.physical_tftp_root

        os.mkdir(image_root)

        if FLAGS.physical_pxe_vlan_per_host:
            parent_interface = FLAGS.physical_pxe_parent_interface
            pxe_ip_id = db.phy_pxe_ip_associate(context, host.id)
            pxe_ip = db.phy_pxe_ip_get(context, pxe_ip_id)
            vlan_num = host.pxe_vlan_id
            server_address = pxe_ip.server_address
            client_address = pxe_ip.address
            tftp_root = os.path.join(tftp_root, str(instance['id']))

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

            #execute('ip', 'address',
            #        'add', server_address,
            #        'peer', client_address,
            #        'dev', pxe_interface,
            #        run_as_root=True)
            #execute('ip', 'link', 'set', pxe_interface, 'up', run_as_root=True)
            execute('ip', 'address',
                    'add', server_address + '/24',
                    'dev', pxe_interface,
                    run_as_root=True)
            execute('ip', 'route', 'add',
                    client_address, 'scope', 'host', 'dev', pxe_interface,
                    run_as_root=True)

            os.mkdir(tftp_root)
            shutil.copyfile(FLAGS.physical_pxelinux_path, os.path.join(tftp_root, 'pxelinux.0'))
            os.mkdir(os.path.join(tftp_root, 'pxelinux.cfg'))

            pxe.start_pxe_server(interface=pxe_interface,
                                 tftp_root=tftp_root,
                                 client_address=client_address,
                                 pid_path=_dnsmasq_pid_path(pxe_interface),
                                 lease_path=_dnsmasq_lease_path(pxe_interface))
        
        self.plug_vifs(instance, network_info)

        ifcfgs = []
        if_num = -1
        for (network,mapping) in network_info:
            LOG.debug("mapping['mac'] = %s", mapping['mac'])
            if_num += 1
            device = "eth%d" % if_num
            pif = db.phy_interface_get_by_vif_uuid(context, mapping['vif_uuid'])
            if not pif:
                LOG.warn("vif_uuid:%s dose not associated to pif, unexpectedly", mapping['vif_uuid'])
                continue
            ifcfg = _build_ifcfg_string_from_mapping(device, pif.address, mapping)
            if FLAGS.physical_use_unsafe_vlan and mapping['should_create_vlan'] and network.get('vlan'):
                ifcfg += "," + network['vlan']
            LOG.debug("ifcfg: %s", ifcfg)
            ifcfgs.append(ifcfg)

        self._firewall_driver.setup_basic_filtering(instance, network_info)
        self._firewall_driver.update_instance_filter(instance, network_info)

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

        LOG.debug("fetching image id=%s target=%s", ami_id, image_target)
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

        LOG.debug("fetching deploy_kernel id=%s target=%s", aki_id, kernel_target)
        self._cache_image_x(context=context,
                          image_id=deploy_aki_id,
                          target=deploy_kernel_target,
                          user_id=instance['user_id'],
                          project_id=instance['project_id'])

        LOG.debug("fetching deploy_ramdisk id=%s target=%s", ari_id, ramdisk_target)
        self._cache_image_x(context=context,
                          image_id=deploy_ari_id,
                          target=deploy_ramdisk_target,
                          user_id=instance['user_id'],
                          project_id=instance['project_id'])

        LOG.debug("fetching images all done")

        pxe_config_path = os.path.join(tftp_root, 'pxelinux.cfg', "01-" + host.pxe_mac_address.replace(":", "-").lower())

        root_mb = instance['root_gb'] * 1024

        inst_type_id = instance['instance_type_id']
        inst_type = instance_types.get_instance_type(inst_type_id)
        swap_mb = inst_type['swap']
        if swap_mb < 1024:
            swap_mb = 1024

        deployment_key = _random_alnum(32)
        deployment_id = db.phy_deployment_create(context, deployment_key, image_target, pxe_config_path, root_mb, swap_mb)

        # 'default deploy' will be replaced to 'default boot' by phy_deploy_work
        pxeconf = "default deploy\n"
        pxeconf += "\n"

        pxeconf += "label deploy\n"
        pxeconf += "kernel %s\n" % deploy_aki_id
        pxeconf += "append"
        pxeconf += " initrd=%s" % deploy_ari_id
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

        f = open(pxe_config_path, 'w')
        f.write(pxeconf)
        f.close()

        if not host.ipmi_address:
            LOG.warn("Since ipmi_address is empty, power_off_on is not performed")

        LOG.debug("power on")
        pm = _get_ipmi(host.ipmi_address, host.ipmi_user, host.ipmi_password)
        state = pm.power_off()
        self._update_physical_state(context, host, instance, state)
        state = pm.power_on()
        self._update_physical_state(context, host, instance, state)

        if FLAGS.physical_console:
            (out,err) = execute(FLAGS.physical_console,
                                '--ipmi_address=%s' % host.ipmi_address,
                                '--ipmi_user=%s' % host.ipmi_user,
                                '--ipmi_password=%s' % host.ipmi_password,
                                '--terminal_port=%s' % host.terminal_port,
                                '--pidfile=%s' % _console_pidfile(host.id),
                                run_as_root=True)

            LOG.debug("physical_console: out=%s", out)
            LOG.debug("physical_console: err=%s", err)

    def reboot(self, instance, network_info):
        host = self._get_phy_host_by_instance_id(instance.id)
        
        if not host:
            raise exception.InstanceNotFound(instance_id=instance.id)

        ctx = nova_context.get_admin_context()
        pm = _get_ipmi(host.ipmi_address, host.ipmi_user, host.ipmi_password)
        state = pm.power_off()
        self._update_physical_state(ctx, host, instance, state)
        state = pm.power_on()
        self._update_physical_state(ctx, host, instance, state)

    def get_host_ip_addr(self):
        return None

    def rescue(self, context, instance, callback, network_info):
        pass

    def unrescue(self, instance, callback, network_info):
        pass

    def poll_rescued_instances(self, timeout):
        pass

    def destroy(self, instance, network_info, block_device_info=None):
        LOG.debug("destroy: instance=%s", instance.__dict__)
        ctx = nova_context.get_admin_context()
        host = self._get_phy_host_by_instance_id(instance.id)
        if not host:
            LOG.warning("Instance:id='%s' not found" % instance.id)
            return
        pm = _get_ipmi(host.ipmi_address, host.ipmi_user, host.ipmi_password)
        state = pm.power_off()
        self._update_physical_state(ctx, host, None, state)

        self._firewall_driver.unfilter_instance(instance,
                                                network_info=network_info)

        for (network, mapping) in network_info:
            self._vif_driver.unplug(instance, network, mapping)

        image_root = os.path.join(FLAGS.instances_path, str(instance['id']))
        shutil.rmtree(image_root, ignore_errors=True)

        tftp_root = FLAGS.physical_tftp_root
        if FLAGS.physical_pxe_vlan_per_host:
            vlan_num = host.pxe_vlan_id
            pxe_interface = 'vlan%d' % vlan_num
            tftp_root = tftp_root + '/' + str(instance.id)
            
            dnsmasq_pid = _dnsmasq_pid(pxe_interface)
            if dnsmasq_pid:
                execute(FLAGS.physical_kill_dnsmasq_path, str(dnsmasq_pid), run_as_root=True)
            _unlink_without_raise(_dnsmasq_pid_path(pxe_interface))
            _unlink_without_raise(_dnsmasq_lease_path(pxe_interface))                
            
            execute('ip', 'link', 'set', pxe_interface, 'down', run_as_root=True)
            execute('vconfig', 'rem', pxe_interface, run_as_root=True)
            
            shutil.rmtree(tftp_root, ignore_errors=True)

            from nova.network import linux_net
            chain = 'phy-%s' % pxe_interface
            iptables = linux_net.iptables_manager
            iptables.ipv4['filter'].remove_chain(chain)
            iptables.apply()            
        else:
            pxe_config_path = os.path.join(tftp_root, "pxelinux.cfg", "01-" + host.pxe_mac_address.replace(":", "-").lower())
            _unlink_without_raise(pxe_config_path)

        db.phy_pxe_ip_disassociate(ctx, host.id)

        console_pid = _console_pid(host.id)
        if console_pid:
            execute('kill', str(console_pid), run_as_root=True, check_exit_code=[0,1])
        _unlink_without_raise(_console_pidfile(host.id))


    def _create_iscsi_export_tgtadm(self, path, tid, iqn):
        LOG.debug("_create_iscsi_export_tgtadm: %s", locals())
        utils.execute('tgtadm', '--lld', 'iscsi',
                      '--mode', 'target',
                      '--op', 'new',
                      '--tid', tid,
                      '--targetname', iqn,
                      run_as_root=True)
        utils.execute('tgtadm', '--lld', 'iscsi',
                      '--mode', 'logicalunit',
                      '--op', 'new',
                      '--tid', tid,
                      '--lun', '1',
                      '--backing-store', path,
                      run_as_root=True)

    def _allow_iscsi_tgtadm(self, tid, address):
        LOG.debug("_allow_iscsi_tgtadm: %s", locals())
        utils.execute('tgtadm', '--lld', 'iscsi',
                      '--mode', 'target',
                      '--op', 'bind',
                      '--tid', tid,
                      '--initiator-address', address,
                      run_as_root=True)

    def _delete_iscsi_export_tgtadm(self, tid):
        LOG.debug("_delete_iscsi_export_tgtadm: %s", locals())
        try:
            utils.execute('tgtadm', '--lld', 'iscsi',
                      '--mode', 'logicalunit',
                      '--op', 'delete',
                      '--tid', tid,
                      '--lun', '1',
                      run_as_root=True)
        except:
            pass
        try:
            utils.execute('tgtadm', '--lld', 'iscsi',
                      '--mode', 'target',
                      '--op', 'delete',
                      '--tid', tid,
                      run_as_root=True)
        except:
            pass
        # check if tid is deleted
        # If tid is deleted (or has been deleted) tgtadm returns with status==22.
        execute('tgtadm', '--lld', 'iscsi',
                '--mode', 'target',
                '--op', 'show',
                '--tid', tid,
                check_exit_code=22,
                run_as_root=True)

    def _volume_id_from_device_path(self, device_path):
        import re
        m = re.search(r':volume-([0-9A-Fa-f]+)', device_path)
        if m:
            return int(m.group(1), 16)
        return None

    def attach_volume(self, instance_name, device_path, mountpoint):
        LOG.info("attach_volume: instance_name=%s device_path=%s mountpoint=%s", instance_name,device_path,mountpoint)
        i = self._get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        ctx = nova_context.get_admin_context()
        pxe_ip = db.phy_pxe_ip_get_by_phy_host_id(ctx, i.id)
        if not pxe_ip:
            if not FLAGS.physical_use_unsafe_iscsi:
                raise exception.Error("No fixed PXE IP is associated to phy_instance:%s" % instance_name)
        volume_id = self._volume_id_from_device_path(device_path)
        tid = volume_id
        mpstr = mountpoint.replace('/', '.').strip('.')
        iqn = 'iqn.2010-10.org.openstack:%s-%s' % (tid, mpstr)
        self._create_iscsi_export_tgtadm(device_path, tid, iqn)
        if pxe_ip:
            self._allow_iscsi_tgtadm(tid, pxe_ip.address)
        else:
            # unsafe
            self._allow_iscsi_tgtadm(tid, 'ALL')
        return True

    def _volume_id_from_instance_name_and_mountpoint(self, instance_name, mountpoint):
        ctx = nova_context.get_admin_context()
        phy_host = self._get_phy_host_by_instance_name(instance_name)
        if not phy_host:
            return None
        for vol in db.volume_get_all_by_instance(ctx, phy_host.instance.id):
            if vol.mountpoint == mountpoint:
                return vol.id
        return None

    @exception.wrap_exception()
    def detach_volume(self, instance_name, mountpoint):
        LOG.info("detach_volume: instance_name=%s mountpoint=%s", instance_name,mountpoint)
        tid = self._volume_id_from_instance_name_and_mountpoint(instance_name, mountpoint)
        if not tid:
            LOG.warn("cannot find volume for instance_name=%s and mountpoint=%s", instance_name, mountpoint)
            return
        self._delete_iscsi_export_tgtadm(tid)

    def get_info(self, instance):
        h = self._get_phy_host_by_instance_id(instance['id'])
        if not h:
            raise exception.InstanceNotFound(instance_id=instance['id'])
        pm = _get_ipmi(h.ipmi_address, h.ipmi_user, h.ipmi_password)
        ps = power_state.SHUTOFF
        if pm.is_power_on():
            ps = power_state.RUNNING
        LOG.debug("power_state=%s", ps)
        return {'state': ps,
                'max_mem': h['memory_mb'],
                'mem': h['memory_mb'],
                'num_cpu': h['cpus'],
                'cpu_time': 0}

    def get_diagnostics(self, instance_name):
        i = self._get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        return {}

    def list_disks(self, instance_name):
        i = self._get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        return ['A_DISK']

    def list_interfaces(self, instance_name):
        i = self._get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        return ['A_VIF']

    def block_stats(self, instance_name, disk_id):
        i = self._get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        return [0L, 0L, 0L, 0L, None]

    def interface_stats(self, instance_name, iface_id):
        i = self._get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        return [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L]

    def get_console_output(self, instance):
        return 'FAKE CONSOLE\xffOUTPUT'

    def get_ajax_console(self, instance):
        return {'token': 'FAKETOKEN',
                'host': 'fakeajaxconsole.com',
                'port': 6969}

    def get_vnc_console(self, instance):
        return {'token': 'FAKETOKEN',
                'host': 'fakevncconsole.com',
                'port': 6969}

    def get_console_pool_info(self, console_type):
        return  {'address': '127.0.0.1',
                 'username': 'fakeuser',
                 'password': 'fakepassword'}

    def refresh_security_group_rules(self, security_group_id):
        self._firewall_driver.refresh_security_group_rules(security_group_id)
        return True

    def refresh_security_group_members(self, security_group_id):
        self._firewall_driver.refresh_security_group_members(security_group_id)
        return True

    def refresh_provider_fw_rules(self):
        self._firewall_driver.refresh_provider_fw_rules()
        pass
    
    def _sum_phy_hosts(self, ctxt):
        vcpus = 0
        vcpus_used = 0
        memory_mb = 0
        memory_mb_used = 0
        local_gb = 0
        local_gb_used = 0        
        for i in self._get_phy_hosts(ctxt):
            if i.registration_status != 'done':
                continue
            vcpus += i.cpus
            memory_mb += i.memory_mb
            local_gb += i.local_gb

        dic = {'vcpus': vcpus,
               'memory_mb': memory_mb,
               'local_gb': local_gb,
               'vcpus_used': vcpus_used,
               'memory_mb_used': memory_mb_used,
               'local_gb_used': local_gb_used,
               }
        return dic

    def _max_phy_resouces(self, ctxt):
        max_cpus = 0
        max_memory_mb = 0
        max_local_gb = 0
        
        for i in self._get_phy_hosts(ctxt):
            if i.registration_status != 'done' or i.instance_id:
                continue
            
            #put prioirty to memory size. You can use CPU and HDD, if you change the following line.
            if max_memory_mb > i.memory_mb:
                max_memory_mb = i.momory_mb
                max_cpus = i.cpus
                max_local_gb = i.max_local_gb

        dic = {'vcpus': max_cpus,
               'memory_mb': max_memory_mb,
               'local_gb': max_local_gb,
               'vcpus_used': 0,
               'memory_mb_used': 0,
               'local_gb_used': 0,
               }
        return dic

    def update_available_resource(self, ctxt, host):
        """Updates compute manager resource info on ComputeNode table.

        This method is called when nova-coompute launches, and
        whenever admin executes "nova-manage service update_resource".

        :param ctxt: security context
        :param host: hostname that compute manager is currently running

        """

        dic = self._max_phy_resouces(ctxt)
        #dic = self._sum_phy_hosts(ctxt)
        dic['hypervisor_type'] = 'physical'
        dic['hypervisor_version'] = 1
        dic['cpu_info'] = 'physical cpu'
        
        try:
            service_ref = db.service_get_all_compute_by_host(ctxt, host)[0]
        except exception.NotFound:
            raise exception.ComputeServiceUnavailable(host=host)

        dic['service_id'] = service_ref['id']

        compute_node_ref = service_ref['compute_node']
        if not compute_node_ref:
            LOG.info(_('Compute_service record created for %s ') % host)
            db.compute_node_create(ctxt, dic)
        else:
            LOG.info(_('Compute_service record updated for %s ') % host)
            db.compute_node_update(ctxt, compute_node_ref[0]['id'], dic)

    def ensure_filtering_rules_for_instance(self, instance_ref, network_info):
        self._firewall_driver.setup_basic_filtering(instance_ref, network_info)
        self._firewall_driver.update_instance_filter(instance_ref, network_info)

    def unfilter_instance(self, instance_ref, network_info):
        self._firewall_driver.unfilter_instance(instance_ref,
                                                network_info=network_info)

    def test_remove_vm(self, instance_name):
        """ Removes the named VM, as if it crashed. For testing"""
        LOG.info(_("test_remove_vm: instance_name=%s") % (instance_name))
        raise exception.InstanceNotFound(instance_id=instance_name)

    def _get_host_stats(self):
        dic = self._max_phy_resouces(nova_context.get_admin_context())
        memory_total = dic['memory_mb'] * 1024 * 1024
        memory_free = (dic['memory_mb'] - dic['memory_mb_used']) * 1024 * 1024
        disk_total = dic['local_gb'] * 1024 * 1024 * 1024
        disk_used = dic['local_gb_used'] * 1024 * 1024 * 1024
        return {
          'host_name-description': 'baremetal ' + FLAGS.host,
          'host_hostname': FLAGS.host,
          'host_memory_total': memory_total,
          'host_memory_overhead': 0,
          'host_memory_free': memory_free,
          'host_memory_free_computed': memory_free,
          'host_other_config': {},
#          'host_ip_address': '192.168.1.109',
#          'host_cpu_info': {},
          'disk_available': disk_total - disk_used,
          'disk_total': disk_total,
          'disk_used': disk_used,
#          'host_uuid': 'cedb9b39-9388-41df-8891-c5c9a0c0fe5f',
          'host_name_label': FLAGS.host,
          'type': 'physical',
          }

    def update_host_status(self):
        LOG.info(_("update_host_status:"))
        return self._get_host_stats()

    def get_host_stats(self, refresh=False):
        LOG.info(_("get_host_stats: refresh=%s") % (refresh))
        return self._get_host_stats()

    def host_power_action(self, host, action):
        """Reboots, shuts down or powers up the host."""
        LOG.info(_("host_power_action: host=%s action=%s") % (host, action))
        pass

    def set_host_enabled(self, host, enabled):
        """Sets the specified host's ability to accept new instances."""
        LOG.info(_("set_host_enabled: host=%s enabled=%s") % (host, enabled))
        pass

    def _fetch_image(self, context, target, image_id, user_id, project_id):
        """Grab image and optionally attempt to resize it"""
        images.fetch_to_raw(context, image_id, target, user_id, project_id)

    def _cache_image_x(self, context, target, image_id, user_id, project_id):
        """Grab image and optionally attempt to resize it"""
        if not os.path.exists(target):
            self._fetch_image(context, target, image_id, user_id, project_id)

    def plug_vifs(self, instance, network_info):
        """Plugin VIFs into networks."""
        LOG.debug("plug_vifs: %s", locals())
        for (network, mapping) in network_info:
            self._vif_driver.plug(instance, network, mapping)

    def _update_physical_state(self, context, host, instance, state):
        instance_id = None
        if instance:
            instance_id = instance.id
        db.phy_host_update(context, host.id,
            {'instance_id': instance_id,
            'task_state' : state,
            })

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
           rules += 'SUBSYSTEM=="net", ACTION=="add", DRIVERS=="?*", ATTR{address}=="%s", ATTR{dev_id}=="0x0", ATTR{type}=="1", KERNEL=="eth*", NAME="eth%d"\n' % (hwaddr,i)
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
            net_info = {'name': 'eth%d' % ifc_num,
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

""" end add by NTT DOCOMO """
