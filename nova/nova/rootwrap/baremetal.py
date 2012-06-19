
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

from nova.rootwrap import filters

filterlist = [
    filters.CommandFilter("/sbin/ip", "root"),
    filters.CommandFilter("/sbin/vconfig", "root"),
    filters.CommandFilter("/user/bin/ipmitool", "root"),
    filters.RegExpFilter("phy_console", "root", ".*/phy_console", "--instance_id=.*", "--pidfile=.*"),
    filters.RegExpFilter("phy_console", "root", ".*/phy_console",
                         "--ipmi_address=.*",
                         "--ipmi_user=.*",
                         "--ipmi_password=.*",
                         "--terminal_port=.*",
                         "--pidfile=.*"),
    filters.RegExpFilter("phy_kill_dnsmasq", "root", ".*/phy_kill_dnsmasq", "[0-9]+"),
    filters.RegExpFilter("phy_kill_shellinaboxd", "root", ".*/phy_kill_shellinaboxd", "[0-9]+"),
    ]

""" end add by NTT DOCOMO """

