
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
    

class IpmiError(Exception):
    def __init__(self, status, message):
        self.status = status
        self.message = message

    def __str__(self):
        return "%s: %s" % (self.status, self.message)


class Ipmi:

    def __init__(self,address,user,password,interface="lanplus"):
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

    def power_on(self):
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

    def power_off(self):
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


class DummyIpmi:

    def __init__(self):
        pass

    def power_on(self):
        return physical_states.ACTIVE

    def power_off(self):
        return physical_states.DELETED

    def is_power_off(self):
        return True

    def is_power_on(self):
        return True

""" end add by NTT DOCOMO """
