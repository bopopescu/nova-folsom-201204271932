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
from nova.virt.vif import VIFDriver

from nova import context
from nova.virt.baremetal import bmdb
from nova import exception

FLAGS = flags.FLAGS

LOG = logging.getLogger(__name__)

class PhyVIFDriver(VIFDriver):

    def _after_plug(self, instance, network, mapping, pif):
        pass

    def _after_unplug(self, instance, network, mapping, pif):
        pass

    def plug(self, instance, network, mapping):
        LOG.debug("plug: %s", locals())
        ctx = context.get_admin_context()
        ph = bmdb.phy_host_get_by_instance_id(ctx, instance['id'])
        if not ph:
            return
        pifs = bmdb.phy_interface_get_all_by_phy_host_id(ctx, ph['id'])
        for pif in pifs:
            if not pif['vif_uuid']:
                bmdb.phy_interface_set_vif_uuid(ctx, pif['id'], mapping.get('vif_uuid'))
                LOG.debug("pif:%s is plugged (vif_uuid=%s)", pif['id'], mapping.get('vif_uuid'))
                self._after_plug(instance, network, mapping, pif)
                return
        raise exception.Error("phy_host:%s has no vacant pif for vif_uuid=%s" % (ph['id'], mapping['vif_uuid']))

    def unplug(self, instance, network, mapping):
        LOG.debug("unplug: %s", locals())
        ctx = context.get_admin_context()
        pif = bmdb.phy_interface_get_by_vif_uuid(ctx, mapping['vif_uuid'])
        if pif:
            bmdb.phy_interface_set_vif_uuid(ctx, pif['id'], None)
            LOG.debug("pif:%s is unplugged (vif_uuid=%s)", pif['id'], mapping.get('vif_uuid'))
            self._after_unplug(instance, network, mapping, pif)
        else:
            LOG.warn("no pif for vif_uuid=%s" % mapping['vif_uuid'])

""" end add by NTT DOCOMO """
