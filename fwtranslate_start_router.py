#! /usr/bin/python

################################################################################
# flexiWAN SD-WAN software - flexiEdge, flexiManage.
# For more information go to https://flexiwan.com
#
# Copyright (C) 2019  flexiWAN Ltd.
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.
# See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
################################################################################

import os
import re

import fwglobals
import fwutils

# start_router
# --------------------------------------
# Translates request:
#
#    {
#      "entity": "agent",
#      "message": "start-router",
#      "params": {
#        "interfaces": [
#           {
#               "name":"0000:00:08.00",
#               "addr":"10.0.0.4/24"
#           },
#           {
#               "name":"0000:00:09.00",
#               "addr":"192.168.56.101/24",
#               "routing":"ospf"
#           }
#        ],
#        "routes": [
#           {
#             "addr": "default",
#             "via": "10.0.0.10"
#           },
#           {
#             "addr": "9.9.9.9",
#             "via": "192.168.56.102",
#             "pci":"0000:00:09.00"
#           }
#        ]
#      }
#    }
#
#    OR
#
#    {
#      "entity": "agent",
#      "message": "start-router",
#      "params": {
#        "pci": [
#           "0000:00:08.00",
#           "0000:00:09.00"
#        ]
#      }
#    }
#|
# into list of commands:
#
#    1. generates ospfd.conf for FRR
#    01. print CONTENT > ospfd.conf
#    ------------------------------------------------------------
#    hostname ospfd
#    password zebra
#    ------------------------------------------------------------
#    log file /var/log/frr/ospfd.log informational
#    log stdout
#    !
#    router ospf
#      ospf router-id 192.168.56.107
#
#    2.Linux_sh1.sh
#    ------------------------------------------------------------
#    02. sudo ip link set dev enp0s8 down &&
#        sudo ip addr flush dev enp0s8
#    03. sudo ip link set dev enp0s9 down &&
#        sudo ip addr flush dev enp0s9
#
#    3.vpp.cfg
#    ------------------------------------------------------------
#    04. sudo systemtctl start vpp
#    05. sudo vppctl enable tap-inject
#
#
def start_router(params=None):
    """Generate commands to start VPP.

     :param params:        Parameters from flexiManage.

     :returns: List of commands.
     """
    cmd_list = []

    # Remove interfaces from Linux.
    #   sudo ip link set dev enp0s8 down
    #   sudo ip addr flush dev enp0s8
    # The interfaces to be removed are stored within 'add-interface' requests
    # in the configuration database.
    pci_list = []
    for key in fwglobals.g.router_api.db_requests.db:
        if re.match('add-interface', key):
            (_, params) = fwglobals.g.router_api.db_requests.fetch_request(key)
            iface_pci  = fwutils.pci_to_linux_iface(params['pci'])
            if iface_pci:
                cmd = {}
                cmd['cmd'] = {}
                cmd['cmd']['name']    = "exec"
                cmd['cmd']['params']  = [ "sudo ip link set dev %s down && sudo ip addr flush dev %s" % (iface_pci ,iface_pci ) ]
                cmd['cmd']['descr']   = "shutdown dev %s in Linux" % iface_pci
                cmd['revert'] = {}
                cmd['revert']['name']    = "exec"
                cmd['revert']['params']  = [ "sudo netplan apply" ]
                cmd['revert']['descr']  = "apply netplan configuration"
                cmd_list.append(cmd)

            # If device is not vmxnet3 device, add it to list of devices
            # that will be add to the /etc/vpp/startup.conf.
            # The vmxnet3 devices should not appear in startup.conf.
            # Othervise vpp will capture them with vfio-pci driver,
            # and 'create interface vmxnet3' will fail with 'device in use'.
            device_driver = params.get('driver')
            if device_driver is None or device_driver != 'vmxnet3':
                pci_list.append(params['pci'])

    vpp_filename = fwglobals.g.VPP_CONFIG_FILE

    # Add interfaces to the vpp configuration file, thus creating whitelist.
    # If whitelist exists, on bootup vpp captures only whitelisted interfaces.
    # Other interfaces will be not captured by vpp even if they are DOWN.
    if len(pci_list) > 0:
        cmd = {}
        cmd['cmd'] = {}
        cmd['cmd']['name']    = "python"
        cmd['cmd']['descr']   = "add devices to %s" % vpp_filename
        cmd['cmd']['params']  = {
            'module': 'fwutils',
            'func'  : 'vpp_startup_conf_add_devices',
            'args'  : { 'vpp_config_filename' : vpp_filename, 'devices': pci_list }
        }
        cmd['revert'] = {}
        cmd['revert']['name']   = "python"
        cmd['revert']['descr']  = "remove devices from %s" % vpp_filename
        cmd['revert']['params'] = {
            'module': 'fwutils',
            'func'  : 'vpp_startup_conf_remove_devices',
            'args'  : { 'vpp_config_filename' : vpp_filename, 'devices': pci_list }
        }
        cmd_list.append(cmd)

    # Enable NAT in vpp configuration file
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "python"
    cmd['cmd']['descr']   = "add NAT to %s" % vpp_filename
    cmd['cmd']['params']  = {
        'module': 'fwutils',
        'func'  : 'vpp_startup_conf_add_nat',
        'args'  : { 'vpp_config_filename' : vpp_filename }
    }
    cmd['revert'] = {}
    cmd['revert']['name']   = "python"
    cmd['revert']['descr']  = "remove NAT from %s" % vpp_filename
    cmd['revert']['params'] = {
        'module': 'fwutils',
        'func'  : 'vpp_startup_conf_remove_nat',
        'args'  : { 'vpp_config_filename' : vpp_filename }
    }
    cmd_list.append(cmd)

    # Create commands that start vpp and configure it with addresses
    #   sudo systemtctl start vpp
    #   <connect to python bindings of vpp and than run the rest>
    #   sudo vppctl enable tap-inject
    cmd = {}
    cmd['cmd'] = {}                     # vfio-pci related stuff is needed for vmxnet3 interfaces
    cmd['cmd']['name']    = "exec"
    cmd['cmd']['params']  = [ 'sudo modprobe vfio-pci  &&  (echo Y | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode)' ]
    cmd['cmd']['descr']   = "enable vfio-pci driver in Linux"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "exec"
    cmd['cmd']['params']  = [ 'sudo systemctl start vpp; if [ -z "$(pgrep vpp)" ]; then exit 1; fi' ]
    cmd['cmd']['descr']   = "start vpp"
    cmd['revert'] = {}
    cmd['revert']['name']   = "stop_router"
    cmd['revert']['descr']  = "stop router"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "connect_to_router"
    cmd['cmd']['descr']   = "connect to vpp papi"
    cmd['revert'] = {}
    cmd['revert']['name']   = "disconnect_from_router"
    cmd['revert']['descr']  = "disconnect from vpp papi"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "exec"
    cmd['cmd']['params']  = [ "sudo vppctl enable tap-inject" ]
    cmd['cmd']['descr']   = "enable tap-inject"
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = "nat44_forwarding_enable_disable"
    cmd['cmd']['descr']   = "enable NAT forwarding"
    cmd['cmd']['params']  = { 'enable':1 }
    cmd_list.append(cmd)
    cmd = {}
    cmd['cmd'] = {}
    cmd['cmd']['name']    = 'exec'
    cmd['cmd']['params']  = [ 'sudo netplan apply' ]
    cmd['cmd']['descr']   = "netplan apply"
    cmd_list.append(cmd)

    return cmd_list

def get_request_key(*params):
    """Get start router command key.

     :param params:        Parameters from flexiManage.

     :returns: A key.
     """
    return 'start-router'
