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

from nova import log as logging
from nova import utils
from nova import flags

from nova.virt.phy import physical_states

import os
import time
import tempfile


FLAGS = flags.FLAGS
LOG = logging.getLogger('nova.virt.phy.ipmi')

def get_power_manager(**kwargs):
    return Ipmi(**kwargs)

def get_power_manager_dummy(**kwargs):
    return DummyIpmi(**kwargs)

def make_password_file(password):
    fd_path = tempfile.mkstemp()
    f = open(fd_path[1], "w")
    f.write(password)
    f.close()
    return fd_path[1]

def exec_ipmi(command,host,user,password,interface="lanplus"):
    args = []
    args.append("ipmitool")
    args.append("-I")
    args.append(interface)
    args.append("-H")
    args.append(host)
    args.append("-U")
    args.append(user)
    args.append("-f")
    pwfile = make_password_file(password)
    args.append(pwfile)
    args.extend(command.split(" "))
    LOG.debug("args: %s", args)
    out,err = utils.execute(*args, attempts=3)
    os.unlink(pwfile)
    return (out,err)


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

    def __init__(self,address=None,user=None,password=None,interface="lanplus"):
        if address == None:
            raise IpmiError, (-1, "address is None")
        if user == None:
            raise IpmiError, (-1, "user is None")
        if password == None:
            raise IpmiError, (-1, "password is None")
        if interface == None:
            raise IpmiError, (-1, "interface is None")
        self.host = address
        self.user = user
        self.password = password
        self.interface = interface

    def _exec_ipmi(self,command):
        out,err = exec_ipmi(command,
                            self.host,
                            self.user,
                            self.password,
                            self.interface)
        LOG.debug("out: %s", out)
        LOG.debug("err: %s", err)
        return out, err
    
    def activate_node(self):
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
        try:
            self._exec_ipmi("power on")
        except Exception as ex:
            LOG.exception("power_on failed", ex)
            return physical_states.ERROR
        return physical_states.ACTIVE
    
    def _no_exception_power_off(self):
        try:
            self._exec_ipmi("power off")
        except Exception as ex:
            LOG.exception("power_off failed", ex)

    def _power_off(self):
        count = 0
        while not self.is_power_off():
            count += 1
            if count > 3:
                return physical_states.ERROR
            self._no_exception_power_off()
            time.sleep(5)
        return physical_states.DELETED

    def _power_status(self):
        out_err = self._exec_ipmi("power status")
        return out_err[0]

    def is_power_off(self):
        r = self._power_status()
        return r == "Chassis Power is off\n"

    def is_power_on(self):
        r = self._power_status()
        return r == "Chassis Power is on\n"
 
    def start_console(self, port, host_id):
        pidfile = self._console_pidfile(host_id)
        
        if FLAGS.physical_console:
            (out,err) = utils.execute(FLAGS.physical_console,
                                '--ipmi_address=%s' % self.host,
                                '--ipmi_user=%s' % self.user,
                                '--ipmi_password=%s' % self.password,
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
        self._power_off()
        state = self.power_on()
        return state

    def _power_on(self):
        return physical_states.ACTIVE

    def _power_off(self):
        return physical_states.DELETED

    def is_power_off(self):
        return True

    def is_power_on(self):
        return True

    def start_console(self, port, host_id):
        pass

    def stop_console(self, host_id):
        pass

""" end add by NTT DOCOMO """
