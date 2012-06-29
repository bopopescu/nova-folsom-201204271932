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

from nova.virt.phy import ipmi

# for FLAGS.baremetal_type
from nova.virt.baremetal import proxy

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
               default='phy_console',
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
    cfg.ListOpt('physical_volume_drivers',
                default=[
                  'iscsi=nova.virt.libvirt.volume.LibvirtISCSIVolumeDriver',
                  'local=nova.virt.libvirt.volume.LibvirtVolumeDriver',
                  'fake=nova.virt.libvirt.volume.LibvirtFakeVolumeDriver',
                  'rbd=nova.virt.libvirt.volume.LibvirtNetVolumeDriver',
                  'sheepdog=nova.virt.libvirt.volume.LibvirtNetVolumeDriver'
                  ],
                help='Baremetal handlers for remote volumes.'),
    cfg.IntOpt('physical_iscsi_tid_offset',
               default=1000000,
               help="offset for iSCSI TID. This offset privents baremetal nova-compute's TID "
                    "from conflicting with nova-volume's one"),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(physical_opts)

LOG = logging.getLogger('nova.virt.physical')


import shlex
import subprocess
from eventlet import greenthread

IQN_PREFIX = 'iqn.2010-10.org.openstack.baremetal'

# the version of execute that checks exitcode even if it is zero 
def _execute_check_zero(*cmd, **kwargs):
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


def get_connection(_):
    return Connection.instance()


def _unlink_without_raise(path):
    try:
        os.unlink(path)
    except OSError:
        LOG.exception("failed to unlink %s" % path)


class NoSuitablePhyHost(exception.NovaException):
    message = _("Failed to find suitable PhyHost")

from nova.virt.baremetal import nodes


def _get_phy_hosts(context):
    service = db.service_get_by_host_and_topic(context, FLAGS.host, "compute")
    if not service:
        LOG.warn("Could not get service_get_by_host_and_topic host=%s topic=%s", FLAGS.host, "compute")
        return []
    phy_hosts = bmdb.phy_host_get_all(context)
    hosts = []
    for host in phy_hosts:
        if host['service_id'] == service['id']:
            hosts.append(host)
    return hosts


def _get_phy_host_by_instance_id(instance_id):
    ctx = nova_context.get_admin_context()
    for host in _get_phy_hosts(ctx):
        if host['instance_id'] == instance_id:
            return host
    return None

    
def _get_phy_host_by_instance_name(instance_name):
    ctx = nova_context.get_admin_context()
    for host in _get_phy_hosts(ctx):
        if not host['instance_id']:
            continue
        try:
            inst = db.instance_get(ctx, host['instance_id'])
            if inst['name'] == instance_name:
                return host
        except exception.InstanceNotFound:
            continue
    return None

    
def _find_suitable_phy_host(context, instance):
    result = None
    for host in _get_phy_hosts(context):
        if host['instance_id']:
            continue
        if host['registration_status'] != 'done':
            continue
        if host['cpus'] < instance.vcpus:
            continue
        if host['memory_mb'] < instance['memory_mb']:
            continue
        if result == None:
            result = host
        else:
            if host['cpus'] < result['cpus']:
                result = host
            elif host['cpus'] == result['cpus'] and host['memory_mb'] < result['memory_mb']:
                result = host
    return result


class Connection(driver.ComputeDriver):
    """Physical hypervisor driver"""

    def __init__(self):
        LOG.info(_("Physical driver __init__"))

        super(Connection, self).__init__()
        self.baremetal_nodes = nodes.get_baremetal_nodes()
        
        self._initiator = None
        self.volume_drivers = {}
        for driver_str in FLAGS.physical_volume_drivers:
            driver_type, _sep, driver = driver_str.partition('=')
            driver_class = utils.import_class(driver)
            self.volume_drivers[driver_type] = driver_class(self)

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

    def get_hypervisor_type(self):
        """Get hypervisor type.

        :returns: hypervisor type (ex. qemu)

        """

        return 'physical'

    def get_hypervisor_version(self):
        """Get hypervisor version.

        :returns: hypervisor version (ex. 12003)

        """

        return 8086

    def list_instances(self):
        l = []
        ctx = nova_context.get_admin_context()
        for host in _get_phy_hosts(ctx):
            if host['instance_id']:
                inst = db.instance_get(ctx, host['instance_id'])
                if inst:
                    l.append(inst['name'])
        return l

    def list_instances_detail(self):
        l = []
        ctx = nova_context.get_admin_context()
        for host in _get_phy_hosts(ctx):
            if host.instance_id:
                pm = nodes.get_power_manager(address=host.ipmi_address,
                                     user=host.ipmi_user,
                                     password=host.ipmi_password,
                                     interface="lanplus")
                ps = power_state.SHUTOFF
                if pm.is_power_on():
                    ps = power_state.RUNNING
                inst = db.instance_get(ctx, host['instance_id'])
                if inst:
                    ii = driver.InstanceInfo(inst['name'], ps)
                    l.append(ii)
        return l
 
    def spawn(self, context, instance, image_meta,
              network_info=None, block_device_info=None):
        LOG.debug("spawn:")
        LOG.debug("instance=%s", instance.__dict__)
        LOG.debug("image_meta=%s", image_meta)
        LOG.debug("network_info=%s", network_info)
        LOG.debug("block_device_info=%s", block_device_info)
       
        ### ISI merge ###
        #start moving to create_domain in dom.py ###
        host = _find_suitable_phy_host(context, instance)

        if not host:
            LOG.info("no suitable physical host found")
            raise NoSuitablePhyHost()

        bmdb.phy_host_update(context, host['id'],
                           {'instance_id': instance['id'],
                            'task_state' : physical_states.BUILDING,
                            })
        #end moving to create_domain in dom.py ###
        
        var = self.baremetal_nodes.define_vars(instance, network_info, block_device_info)

        #start moving to create_domain in XXX.py ###
        self.baremetal_nodes.init_host_nic(var, context, host)
        #end moving to create_domain in dom.py ###
        
        ### no implementation for ISI ###
        self.plug_vifs(instance, network_info)

        #start moving to create_domain in XXX.py ###
        self.baremetal_nodes.start_firewall(var)
        #end moving to create_domain in XXX.py ###

        # similar to self._create_image in proxy.py #
        self.baremetal_nodes.create_image(var, context, image_meta, host)
        # similar to self._create_image in proxy.py #

        self.baremetal_nodes.activate_bootloader(var, context, host)
        
        self.baremetal_nodes.attach_volumes_on_spawn(var)

        # power operation
        if not host.ipmi_address:
            LOG.warn("Since ipmi_address is empty, power_off_on is not performed")

        LOG.debug("power on")

        pm = nodes.get_power_manager(address=host.ipmi_address,
                                     user=host.ipmi_user,
                                     password=host.ipmi_password,
                                     interface="lanplus")
        state = pm.activate_node()

        self._update_physical_state(context, host, instance, state)
        
        pm.start_console(host['terminal_port'], host['id'])

    def reboot(self, instance, network_info):
        host = _get_phy_host_by_instance_id(instance.id)
        
        if not host:
            raise exception.InstanceNotFound(instance_id=instance.id)

        ctx = nova_context.get_admin_context()
        pm = nodes.get_power_manager(address=host.ipmi_address,
                                     user=host.ipmi_user,
                                     password=host.ipmi_password,
                                     interface="lanplus")
        state = pm.reboot_node()
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
        LOG.debug("destroy: network_info=%s", network_info)
        LOG.debug("destroy: block_device_info=%s", block_device_info)
        ctx = nova_context.get_admin_context()

        host = _get_phy_host_by_instance_id(instance.id)
        if not host:
            LOG.warning("Instance:id='%s' not found" % instance.id)
            return
 
        var = self.baremetal_nodes.define_vars(instance, network_info, block_device_info)

        pm = nodes.get_power_manager(address=host.ipmi_address,
                                     user=host.ipmi_user,
                                     password=host.ipmi_password,
                                     interface="lanplus")

        ## stop console
        pm.stop_console(host['id'])
        
        ## power off the host
        state = pm.deactivate_node()

        ## cleanup volumes
        self.baremetal_nodes.detach_volumes_on_destroy(var)

        self.baremetal_nodes.deactivate_bootloader(var, ctx, host)

        self.baremetal_nodes.destroy_images(var)

        self.baremetal_nodes.stop_firewall(var)

        self._unplug_vifs(instance, network_info)
 
        self._update_physical_state(ctx, host, None, state)

    def get_volume_connector(self, instance):
        if not self._initiator:
            self._initiator = libvirt_utils.get_iscsi_initiator()
            if not self._initiator:
                LOG.warn(_('Could not determine iscsi initiator name'),
                         instance=instance)
        return {
            'ip': FLAGS.my_ip,
            'initiator': self._initiator,
        }

    def volume_driver_method(self, method_name, connection_info,
                             *args, **kwargs):
        driver_type = connection_info.get('driver_volume_type')
        if not driver_type in self.volume_drivers:
            raise exception.VolumeDriverNotFound(driver_type=driver_type)
        driver = self.volume_drivers[driver_type]
        method = getattr(driver, method_name)
        return method(connection_info, *args, **kwargs)

    def attach_volume(self, connection_info, instance_name, mountpoint):
        LOG.info("attach_volume: connection_info=%s instance_name=%s mountpoint=%s", connection_info, instance_name, mountpoint)
        host = _get_phy_host_by_instance_name(instance_name)
        if not host:
            raise exception.InstanceNotFound(instance_id=instance_name)
        ctx = nova_context.get_admin_context()
        pxe_ip = bmdb.phy_pxe_ip_get_by_phy_host_id(ctx, host['id'])
        if not pxe_ip:
            if not FLAGS.physical_use_unsafe_iscsi:
                raise exception.Error("No fixed PXE IP is associated to phy_instance:%s" % instance_name)
        mount_device = mountpoint.rpartition("/")[2]
        conf = self.volume_driver_method('connect_volume',
                                         connection_info,
                                         mount_device)
        LOG.debug("conf=%s", conf)
        device_path = connection_info['data']['device_path']
        volume_id = _volume_id_from_device_path(device_path)
        tid = volume_id + FLAGS.physical_iscsi_tid_offset
        mpstr = mountpoint.replace('/', '.').strip('.')
        iqn = '%s:%s-%s' % (IQN_PREFIX, tid, mpstr)
        _create_iscsi_export_tgtadm(device_path, tid, iqn)
        if pxe_ip:
            _allow_iscsi_tgtadm(tid, pxe_ip.address)
        else:
            # unsafe
            _allow_iscsi_tgtadm(tid, 'ALL')
        return True

    def _volume_id_from_instance_name_and_mountpoint(self, instance_name, mountpoint):
        ctx = nova_context.get_admin_context()
        host = _get_phy_host_by_instance_name(instance_name)
        if not host:
            return None
        for vol in db.volume_get_all_by_instance(ctx, host['instance_id']):
            if vol.mountpoint == mountpoint:
                return vol.id
        return None

    @exception.wrap_exception()
    def detach_volume(self, connection_info, instance_name, mountpoint):
        LOG.info("detach_volume: connection_info=%s instance_name=%s mountpoint=%s", connection_info, instance_name, mountpoint)
        mount_device = mountpoint.rpartition("/")[2]
        try:
            volume_id = self._volume_id_from_instance_name_and_mountpoint(instance_name, mountpoint)
            if volume_id:
                tid = volume_id + FLAGS.physical_iscsi_tid_offset
                _delete_iscsi_export_tgtadm(tid)
            else:
                LOG.warn("cannot find volume for instance_name=%s and mountpoint=%s", instance_name, mountpoint)
        finally:
            self.volume_driver_method('disconnect_volume',
                                      connection_info,
                                      mount_device)

    def get_all_block_devices(self):
        """
        Return all block devices in use on this node.
        """
        devdir = '/dev/disk/by-path'
        l = []
        file_list=os.listdir(devdir)
        for f in file_list:
            f = os.path.join(devdir,f)
            l.append(f)
        return l

    def get_info(self, instance):
        host = _get_phy_host_by_instance_id(instance['id'])
        if not host:
            raise exception.InstanceNotFound(instance_id=instance['id'])
        pm = nodes.get_power_manager(address=host.ipmi_address,
                                     user=host.ipmi_user,
                                     password=host.ipmi_password,
                                     interface="lanplus")
        ps = power_state.SHUTOFF
        if pm.is_power_on():
            ps = power_state.RUNNING
        LOG.debug("power_state=%s", ps)
        return {'state': ps,
                'max_mem': host['memory_mb'],
                'mem': host['memory_mb'],
                'num_cpu': host['cpus'],
                'cpu_time': 0}

    def get_diagnostics(self, instance_name):
        i = _get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        return {}

    def list_disks(self, instance_name):
        i = _get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        return ['A_DISK']

    def list_interfaces(self, instance_name):
        i = _get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        return ['A_VIF']

    def block_stats(self, instance_name, disk_id):
        i = _get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        return [0L, 0L, 0L, 0L, None]

    def interface_stats(self, instance_name, iface_id):
        i = _get_phy_host_by_instance_name(instance_name)
        if not i:
            raise exception.InstanceNotFound(instance_id=instance_name)
        return [0L, 0L, 0L, 0L, 0L, 0L, 0L, 0L]

    def get_console_output(self, instance):
        return 'FAKE CONSOLE\xffOUTPUT'

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
        for i in _get_phy_hosts(ctxt):
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
        
        for i in _get_phy_hosts(ctxt):
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
        dic['hypervisor_type'] = self.get_hypervisor_type()
        dic['hypervisor_version'] = self.get_hypervisor_version()
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

    def plug_vifs(self, instance, network_info):
        """Plugin VIFs into networks."""
        LOG.debug("plug_vifs: %s", locals())
        for (network, mapping) in network_info:
            self._vif_driver.plug(instance, network, mapping)

    def _unplug_vifs(self, instance, network_info):
        LOG.debug("_unplug_vifs: %s", locals())
        for (network, mapping) in network_info:
            self._vif_driver.unplug(instance, network, mapping)

    def _update_physical_state(self, context, host, instance, state):
        instance_id = None
        if instance:
            instance_id = instance.id
        bmdb.phy_host_update(context, host.id,
            {'instance_id': instance_id,
            'task_state' : state,
            })


def _create_iscsi_export_tgtadm(path, tid, iqn):
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

def _allow_iscsi_tgtadm(tid, address):
    LOG.debug("_allow_iscsi_tgtadm: %s", locals())
    utils.execute('tgtadm', '--lld', 'iscsi',
                  '--mode', 'target',
                  '--op', 'bind',
                  '--tid', tid,
                  '--initiator-address', address,
                  run_as_root=True)


def _delete_iscsi_export_tgtadm(tid):
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
    _execute_check_zero('tgtadm', '--lld', 'iscsi',
            '--mode', 'target',
            '--op', 'show',
            '--tid', tid,
            check_exit_code=22,
            run_as_root=True)


def _volume_id_from_device_path(device_path):
    import re
    m = re.search(r':volume-([0-9A-Fa-f]+)', device_path)
    if m:
        return int(m.group(1), 16)
    return None


""" end add by NTT DOCOMO """
