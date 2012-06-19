
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

def _execute(*cmd, **kwargs):
    """Wrapper around utils._execute for fake_network."""
    if FLAGS.fake_network:
        LOG.debug('FAKE NET: %s', ' '.join(map(str, cmd)))
        return 'fake', 0
    else:
        return utils.execute(*cmd, **kwargs)

def start_pxe_server(interface, tftp_root, client_address, pid_path, lease_path):
    _execute('dnsmasq',
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
