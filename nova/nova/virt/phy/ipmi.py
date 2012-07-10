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

from nova.openstack.common import cfg
from nova import log as logging
from nova import utils
from nova import flags

from nova.virt.phy import physical_states

import os
import stat
import time
import tempfile

#TODO: rename to baremeteal_xxx
opts = [
    cfg.StrOpt('physical_console',
               default='phy_console',
               help='path to phy_console'),
    cfg.StrOpt('physical_console_pid_dir',
               default='/var/lib/nova/phy/console',
               help='path to directory stores pidfiles of phy_console'),
    ]

FLAGS = flags.FLAGS
FLAGS.register_opts(opts)

LOG = logging.getLogger(__name__)

def get_power_manager(phy_host, **kwargs):
    pm = Ipmi(address=phy_host['ipmi_address'],
              user=phy_host['ipmi_user'],
              password=phy_host['ipmi_password'],
              interface="lanplus")
    return pm

def get_power_manager_dummy(phy_host, **kwargs):
    return DummyIpmi()

def _make_password_file(password):
    fd, path = tempfile.mkstemp()
    os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "w") as f:
        f.write(password)
    return path

def _unlink_without_raise(path):
    try:
        os.unlink(path)
    except OSError:
        LOG.exception("failed to unlink %s" % path)
    

class IpmiError(Exception):
    def __init__(self, status, message):
        self.status = status
        self.message = message

    def __str__(self):
        return "%s: %s" % (self.status, self.message)


class Ipmi:

    def __init__(self, address=None, user=None, password=None, interface="lanplus"):
        if address == None:
            raise IpmiError, (-1, "address is None")
        if user == None:
            raise IpmiError, (-1, "user is None")
        if password == None:
            raise IpmiError, (-1, "password is None")
        if interface == None:
            raise IpmiError, (-1, "interface is None")
        self._address = address
        self._user = user
        self._password = password
        self._interface = interface

    def _exec_ipmitool(self, command):
        args = []
        args.append("ipmitool")
        args.append("-I")
        args.append(self._interface)
        args.append("-H")
        args.append(self._address)
        args.append("-U")
        args.append(self._user)
        args.append("-f")
        pwfile = _make_password_file(self._password)
        try:
            args.append(pwfile)
            args.extend(command.split(" "))
            out,err = utils.execute(*args, attempts=3)
        finally:
            _unlink_without_raise(pwfile)
        LOG.debug("out: %s", out)
        LOG.debug("err: %s", err)
        return out, err
    
    def activate_node(self):
        self._power_off()
        state = self._power_on()
        return state
    
    def reboot_node(self):
        self._power_off()
        state = self._power_on()
        return state

    def deactivate_node(self):
        state = self._power_off()
        return state
    
    def _power_on(self):
        count = 0
        while not self.is_power_on():
            count += 1
            if count > 3:
                return physical_states.ERROR
            try:
                self._exec_ipmitool("power on")
            except Exception as ex:
                LOG.exception("power_on failed", ex)
            time.sleep(5)
        return physical_states.ACTIVE

    def _power_off(self):
        count = 0
        while not self._is_power_off():
            count += 1
            if count > 3:
                return physical_states.ERROR
            try:
                self._exec_ipmitool("power off")
            except Exception as ex:
                LOG.exception("power_off failed", ex)
            time.sleep(5)
        return physical_states.DELETED

    def _power_status(self):
        out_err = self._exec_ipmitool("power status")
        return out_err[0]

    def _is_power_off(self):
        r = self._power_status()
        return r == "Chassis Power is off\n"

    def is_power_on(self):
        r = self._power_status()
        return r == "Chassis Power is on\n"
 
    def start_console(self, port, host_id):
        if FLAGS.physical_console:
            pidfile = self._console_pidfile(host_id)
            (out,err) = utils.execute(FLAGS.physical_console,
                                '--ipmi_address=%s' % self._address,
                                '--ipmi_user=%s' % self._user,
                                '--ipmi_password=%s' % self._password,
                                '--terminal_port=%s' % port,
                                '--pidfile=%s' % pidfile,
                                run_as_root=True)
            LOG.debug("physical_console: out=%s", out)
            LOG.debug("physical_console: err=%s", err)
    
    def stop_console(self, host_id):
        console_pid = self._console_pid(host_id)
        if console_pid:
            utils.execute('kill', str(console_pid), run_as_root=True, check_exit_code=[0,1])
        _unlink_without_raise(self._console_pidfile(host_id))
            
    def _console_pidfile(self, host_id):
        pidfile = "%s/%s.pid" % (FLAGS.physical_console_pid_dir,host_id)
        return pidfile

    def _console_pid(self, host_id):
        pidfile = self._console_pidfile(host_id)
        if os.path.exists(pidfile):
            with open(pidfile, 'r') as f:
                return int(f.read())
        return None


class DummyIpmi:

    def __init__(self):
        pass

    def activate_node(self):
        return physical_states.ACTIVE

    def reboot_node(self):
        return physical_states.ACTIVE

    def deactivate_node(self):
        return physical_states.DELETED

    def is_power_on(self):
        return True

    def start_console(self, port, host_id):
        pass

    def stop_console(self, host_id):
        pass

""" end add by NTT DOCOMO """
