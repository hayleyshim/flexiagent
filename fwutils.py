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

import inspect
import json
import os
import time
import platform
import subprocess
import psutil
import socket
import re
import fwdb_requests
import fwglobals
import fwstats
import shutil
import sys
import yaml
from netaddr import IPNetwork, IPAddress

common_tools = os.path.join(os.path.dirname(os.path.realpath(__file__)) , 'tools' , 'common')
sys.path.append(common_tools)
import fwtool_vpp_startupconf_dict

from fwdb_requests import FwDbRequests

dpdk = __import__('dpdk-devbind')

def get_device_logs(file, num_of_lines):
    """Get device logs.

    :param file:            File name.
    :param num_of_lines:    Number of lines.

    :returns: Return list.
    """
    try:
        cmd = "tail -{} {}".format(num_of_lines, file)
        res = subprocess.check_output(cmd, shell=True).splitlines()

        # On zero matching, res is a list with a single empty
        # string which we do not want to return to the caller
        return res if res != [''] else []
    except (OSError, subprocess.CalledProcessError) as err:
        raise err

def get_agent_version(fname):
    """Get agent version.

    :param fname:           Versions file name.

    :returns: Version value.
    """
    try:
        with open(fname, 'r') as stream:
            versions = yaml.load(stream, Loader=yaml.BaseLoader)
            return versions['components']['agent']['version']
    except:
        err = "get_agent_version: failed to get agent version: %s" % (format(sys.exc_info()[1]))
        fwglobals.log.error(err)
        return None

def get_machine_id():
    """Get machine id.

    :returns: UUID.
    """
    if fwglobals.g.cfg.UUID:    # If UUID is configured manually, use it
        return fwglobals.g.cfg.UUID

    try:                        # Fetch UUID from machine
        if platform.system()=="Windows":
            machine_id = subprocess.check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
        else:
            machine_id = subprocess.check_output(['cat','/sys/class/dmi/id/product_uuid']).decode().split('\n')[0].strip()
        return machine_id.upper()
    except:
        return None

def vpp_pid():
    """Get pid of VPP process.

    :returns:           process identifier.
    """
    try:
        pid = subprocess.check_output(['pidof', 'vpp'])
    except:
        pid = None
    return pid

def vpp_does_run():
    """Check if VPP is running.

    :returns:           Return 'True' if VPP is running.
    """
    runs = True if vpp_pid() else False
    return runs

def af_to_name(af_type):
    """Convert socket type.

    :param af_type:        Socket type.

    :returns: String.
    """
    af_map = {
    	socket.AF_INET: 'IPv4',
    	socket.AF_INET6: 'IPv6',
    	psutil.AF_LINK: 'MAC',
	}
    return af_map.get(af_type, af_type)

def get_os_routing_table():
    """Get routing table.

    :returns: List of routes.
    """
    try:
        routing_table = subprocess.check_output(['route', '-n']).split('\n')
        return routing_table
    except:
        return (None)

def get_default_route():
    """Get default route.

    :returns: Default route.
    """
    try:
        dgw = os.popen('ip route list match default').read()
        rip = dgw.split('default via ')[1].split(' ')[0]
        rdev = dgw.split(' dev ')[1].split(' ')[0]
        return (rip, rdev)
    except:
        return ("", "")

def get_interface_address(iface):
    """Get interface IP address.

    :param iface:        Interface name.

    :returns: IP address.
    """
    addresses = psutil.net_if_addrs()[iface]
    for addr in addresses:
        if addr.family == socket.AF_INET:
            ip   = addr.address
            mask = IPAddress(addr.netmask).netmask_bits()
            return '%s/%s' % (ip, mask)
    raise Exception("get_interface_address(%s): no IPv4 address was found" % iface)

def is_ip_in_subnet(ip, subnet):
    """Check if IP address is in subnet.

    :param ip:            IP address.
    :param subnet:        Subnet address.

    :returns: 'True' if address is in subnet.
    """
    return True if IPAddress(ip) in IPNetwork(subnet) else False

def pci_addr_full(pci_addr):
    """Convert short PCI into full representation.

    :param pci_addr:      Short PCI address.

    :returns: Full PCI address.
    """
    pc = pci_addr.split('.')
    if len(pc) == 2:
        return pc[0]+'.'+"%02x"%(int(pc[1],16))
    return pci_addr

# Convert 0000:00:08.01 provided by management to 0000:00:08.1 used by Linux
def pci_full_to_short(pci):
    """Convert full PCI into short representation.

    :param pci_addr:      Full PCI address.

    :returns: Short PCI address.
    """
    l = pci.split('.')
    if len(l[1]) == 2 and l[1][0] == '0':
        pci = l[0] + '.' + l[1][1]
    return pci

def linux_to_pci_addr(linuxif):
    """Convert Linux interface name into PCI address.

    :param linuxif:      Linux interface name.

    :returns: PCI address.
    """
    NETWORK_BASE_CLASS = "02"
    lines = subprocess.check_output(["lspci", "-Dvmmn"]).splitlines()
    for line in lines:
        vals = line.decode().split("\t", 1)
        if len(vals) == 2:
            # keep slot number
            if vals[0] == 'Slot:':
                slot = vals[1]
            if vals[0] == 'Class:':
                if vals[1][0:2] == NETWORK_BASE_CLASS:
                    interface = pci_to_linux_iface(slot)
                    if interface == linuxif:
                        driver = os.path.realpath('/sys/bus/pci/devices/%s/driver' % slot).split('/')[-1]
                        return (pci_addr_full(slot), "" if driver=='driver' else driver)
    return ("","")

def pci_to_linux_iface(pci):
    """Convert PCI address into Linux interface name.

    :param pci:      PCI address.

    :returns: Linux interface name.
    """
    # igorn@ubuntu-server-1:~$ sudo ls -l /sys/class/net/
    # total 0
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s3 -> ../../devices/pci0000:00/0000:00:03.0/net/enp0s3
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s8 -> ../../devices/pci0000:00/0000:00:08.0/net/enp0s8
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 enp0s9 -> ../../devices/pci0000:00/0000:00:09.0/net/enp0s9
    # lrwxrwxrwx 1 root root 0 Jul  4 16:21 lo -> ../../devices/virtual/net/lo

    # We get 0000:00:08.01 from management and not 0000:00:08.1, so convert a little bit
    pci = pci_full_to_short(pci)

    try:
        output = subprocess.check_output("sudo ls -l /sys/class/net/ | grep " + pci, shell=True)
    except:
        return None
    if output is None:
        return None
    return output.rstrip().split('/')[-1]

def pci_is_vmxnet3(pci):
    """Check if PCI address is vmxnet3.

    :param pci:      PCI address.

    :returns: 'True' if it is vmxnet3, 'False' otherwise.
    """
    # igorn@ubuntu-server-1:~$ sudo ls -l /sys/bus/pci/devices/*/driver
    # lrwxrwxrwx 1 root root 0 Jul 17 22:08 /sys/bus/pci/devices/0000:03:00.0/driver -> ../../../../bus/pci/drivers/vmxnet3
    # lrwxrwxrwx 1 root root 0 Jul 17 23:01 /sys/bus/pci/devices/0000:0b:00.0/driver -> ../../../../bus/pci/drivers/vfio-pci
    # lrwxrwxrwx 1 root root 0 Jul 17 23:01 /sys/bus/pci/devices/0000:13:00.0/driver -> ../../../../bus/pci/drivers/vfio-pci

    # We get 0000:00:08.01 from management and not 0000:00:08.1, so convert a little bit
    pci = pci_full_to_short(pci)

    try:
        # The 'ls -l /sys/bus/pci/devices/*/driver' approach doesn't work well.
        # When vpp starts, it rebinds device to vfio-pci, so 'ls' doesn't detect it.
        # Therefore we go with dpdk-devbind.py. It should be installed on Linux
        # as a part of flexiwan-router installation.
        # When vpp does not run, we get:
        #   0000:03:00.0 'VMXNET3 Ethernet Controller' if=ens160 drv=vmxnet3 unused=vfio-pci,uio_pci_generic
        # When vpp does run, we get:
        #   0000:03:00.0 'VMXNET3 Ethernet Controller' if=ens160 drv=vfio-pci unused=vmxnet3,uio_pci_generic
        #
        #output = subprocess.check_output("sudo ls -l /sys/bus/pci/devices/%s/driver | grep vmxnet3" % pci, shell=True)
        output = subprocess.check_output("sudo dpdk-devbind -s | grep -E '%s .*vmxnet3'" % pci, shell=True)
    except:
        return False
    if output is None:
        return False
    return True


# 'pci_to_vpp_if_name' function maps interface referenced by pci, eg. '0000:00:08.00'
# into name of interface in VPP, eg. 'GigabitEthernet0/8/0'.
# To do that we dump all hardware interfaces, split the dump into list by empty line,
# and search list for interface that includes the pci name.
# The dumps brings following table:
#              Name                Idx    Link  Hardware
# GigabitEthernet0/8/0               1    down  GigabitEthernet0/8/0
#   Link speed: unknown
#   ...
#   pci: device 8086:100e subsystem 8086:001e address 0000:00:08.00 numa 0
#
def pci_to_vpp_if_name(pci):
    """Convert PCI address into VPP interface name.

    :param pci:      PCI address.

    :returns: VPP interface name.
    """
    # vpp_api.cli() throw exception in vpp 19.01 (and work with vpp 19.04)
    # hw = fwglobals.g.router_api.vpp_api.cli("show hardware")
    hw = _vppctl_read('show hardware-interfaces')
    if hw is None:
        raise Exception("pci_to_vpp_if_name: failed to fetch hardware info from VPP")
    for hw_if in re.split(r'\n\s*\n+', hw):
        if re.search(pci, hw_if):
            # In the interface description find line that has word at the beginning.
            # This word is interface name. All the rest of lines start with spaces.
            for line in hw_if.splitlines():
                match = re.match(r'([^\s]+)', line)
                if match:
                    vpp_if_name = match.group(1)
                    break
            return vpp_if_name
    fwglobals.log.debug("pci_to_vpp_if_name(%s): not found in 'sh hard'" % (pci))

    # If no hardware interfaces were found, try vmxnet3 interfaces
    pci_bytes = pci_str_to_bytes(pci)
    hw_1 = fwglobals.g.router_api.vpp_api.vpp.api.vmxnet3_dump()
    for hw_if in hw_1:
        if hw_if.pci_addr == pci_bytes:
            vpp_if_name = hw_if.if_name.rstrip(' \t\r\n\0')
            return vpp_if_name

    fwglobals.log.debug("pci_to_vpp_if_name(%s): sh hard: %s" % (pci, str(hw)))
    fwglobals.log.debug("pci_to_vpp_if_name(%s): sh vmxnet3: %s" % (pci, str(hw_1)))
    return None


# 'pci_str_to_bytes' converts "0000:0b:00.0" string to bytes to pack following struct:
#    struct
#    {
#      u16 domain;
#      u8 bus;
#      u8 slot: 5;
#      u8 function:3;
#    };
#
def pci_str_to_bytes(pci_str):
    """Convert PCI address into bytes.

    :param pci_str:      PCI address.

    :returns: Bytes array.
    """
    list = re.split(r':|\.', pci_str)
    domain   = int(list[0], 16)
    bus      = int(list[1], 16)
    slot     = int(list[2], 16)
    function = int(list[3], 16)
    bytes = ((domain & 0xffff) << 16) | ((bus & 0xff) << 8) | ((slot & 0x1f) <<3 ) | (function & 0x7)
    return socket.htonl(bytes)   # vl_api_vmxnet3_create_t_handler converts parameters by ntoh for some reason (vpp\src\plugins\vmxnet3\vmxnet3_api.c)

# 'pci_to_vpp_sw_if_index' function maps interface referenced by pci, e.g '0000:00:08.00'
# into index of this interface in VPP, eg. 1.
# To do that we convert firstly the pci into name of interface in VPP,
# e.g. 'GigabitEthernet0/8/0', than we dump all VPP interfaces and search for interface
# with this name. If found - return interface index.
def pci_to_vpp_sw_if_index(pci):
    """Convert PCI address into VPP sw_if_index.

    :param pci:      PCI address.

    :returns: sw_if_index.
    """

    vpp_if_name = pci_to_vpp_if_name(pci)
    fwglobals.log.debug("pci_to_vpp_sw_if_index(%s): vpp_if_name: %s" % (pci, str(vpp_if_name)))
    if vpp_if_name is None:
        return None

    sw_ifs = fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_dump()
    for sw_if in sw_ifs:
        if re.match(vpp_if_name, sw_if.interface_name):    # Use regex, as sw_if.interface_name might include trailing whitespaces 
            return  sw_if.sw_if_index
    fwglobals.log.debug("pci_to_vpp_sw_if_index(%s): vpp_if_name: %s" % (pci, yaml.dump(sw_ifs, canonical=True)))
    return None

# 'pci_to_tap' function maps interface referenced by pci, e.g '0000:00:08.00'
# into interface in Linux created by 'vppctl enable tap-inject' command, e.g. vpp1.
# To do that we convert firstly the pci into name of interface in VPP,
# e.g. 'GigabitEthernet0/8/0' and than we grep output of 'vppctl sh tap-inject'
# command by this name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
def pci_to_tap(pci):
    """Convert PCI address into TAP name.

     :param pci:      PCI address.

     :returns: Linux TAP interface name.
     """
    vpp_if_name = pci_to_vpp_if_name(pci)
    if vpp_if_name is None:
        return None
    tap = vpp_if_name_to_tap(vpp_if_name)
    return tap

# 'vpp_if_name_to_tap' function maps name of interface in VPP, e.g. loop0,
# into name of correspondent tap interface in Linux.
# To do that it greps output of 'vppctl sh tap-inject' by the interface name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
#       loop0 -> vpp2
def vpp_if_name_to_tap(vpp_if_name):
    """Convert VPP interface name into Linux TAP interface name.

     :param vpp_if_name:      PCI address.

     :returns: Linux TAP interface name.
     """
    # vpp_api.cli() throw exception in vpp 19.01 (and works in vpp 19.04)
    # taps = fwglobals.g.router_api.vpp_api.cli("show tap-inject")
    taps = _vppctl_read("show tap-inject")
    if taps is None:
        raise Exception("vpp_if_name_to_tap: failed to fetch tap info from VPP")

    pattern = '%s -> ([a-zA-Z0-9]+)' % vpp_if_name
    match = re.search(pattern, taps)
    if match is None:
        return None
    tap = match.group(1)
    return tap

# 'sw_if_index_to_tap' function maps sw_if_index assigned by VPP to some interface,
# e.g '4' into interface in Linux created by 'vppctl enable tap-inject' command, e.g. vpp2.
# To do that we dump all interfaces from VPP, find the one with the provided index,
# take its name, e.g. loop0, and grep output of 'vppctl sh tap-inject' by this name:
#   root@ubuntu-server-1:/# vppctl sh tap-inject
#       GigabitEthernet0/8/0 -> vpp0
#       GigabitEthernet0/9/0 -> vpp1
#       loop0 -> vpp2
def vpp_sw_if_index_to_tap(sw_if_index):
    """Convert VPP sw_if_index into Linux TAP interface name.

     :param sw_if_index:      VPP sw_if_index.

     :returns: Linux TAP interface name.
     """
    for sw_if in fwglobals.g.router_api.vpp_api.vpp.api.sw_interface_dump():
        if sw_if_index == sw_if.sw_if_index:
            tap = vpp_if_name_to_tap(sw_if.interface_name.rstrip(' \t\r\n\0'))
            return tap

def save_file(txt, fname, dir='/tmp'):
    """Save txt to file under a dir (default = /tmp)

     :param txt:      Text.
     :param fname:    File name.
     :param dir:      Folder path.

     :returns: Error message and status code.
     """
    # Make sure fname doesn't include /
    #print ("fname="+fname+", txt="+txt+", dir="+dir)
    if not (isinstance(fname, str) or isinstance(fname, unicode)) or fname.find('/') != -1:
        return {'message':'File name error', 'ok':0}
    datapath = os.path.join(dir, fname)
    if os.path.exists(dir):
        with open(datapath, 'w') as fout:
            fout.write(txt)
        return {'message':'File written', 'ok':1}
    else:
        return {'message':'Directory not exist', 'ok':0}

def _sub_file(fname, smap):
    """Replace words in file.

    :param fname:     File name.
    :param smap:      Dictionary with original and new words.

    :returns: Error message and status code.
    """
    if os.path.exists(fname):
        with open(fname, "r") as sfile:
            data = sfile.readlines()
        txt = ''.join(data)
        for k,v in smap.items():
            txt = txt.replace(k,v)
        with open(fname, "w") as sfile:
            sfile.write(txt)
        return {'message':'File substituted', 'ok':1}
    else:
        return {'message':'File does not exist', 'ok':0}

def _vppctl_read(cmd, wait=True):
    """Read command from VPP.

    :param cmd:       Command to execute (not including vppctl).
    :param wait:      Whether to wait until command succeeds.

    :returns: Output returned bu vppctl.
    """
    retries = 200
    retries_sleep = 1
    if wait == False:
        retries = 1
        retries_sleep = 0
    # make sure socket exists
    for _ in range(retries):
        if os.path.exists("/run/vpp/cli.sock"):
            break
        time.sleep(retries_sleep)
    if not os.path.exists("/run/vpp/cli.sock"):
        return None
    # make sure command succeeded, try up to 200 iterations
    for _ in range(retries):
        try:
            _ = open(os.devnull, 'r+b', 0)
            handle = os.popen('sudo vppctl ' + cmd + ' 2>/dev/null')
            data = handle.read()
            retcode = handle.close()
            if retcode == None or retcode == 0:  # Exit OK
                break
        except:
            return None
        time.sleep(retries_sleep)
    if retcode: # not succeeded after 200 retries
        return None
    return data

def tap_sub_file(fname):
    """Substitute a file with tap VPP names.

    :param fname:      File name.

    :returns: Error message and status code.
    """
    taps = _vppctl_read('sh tap-inject')
    if taps == None:
        return {'message':'Tap read error', 'ok':0}
    if_map = {}
    tap_split = taps.split('\r\n')[:-1]
    if len(tap_split) == 0:
        return {'message':'No taps found', 'ok':0}
    for m in tap_split:
        ifs = m.split(' -> ')
        if len(ifs) != 2:
            return {'message':'Tap mapping error', 'ok':0}
        if_map[ifs[0]] = ifs[1]
    return _sub_file(fname, if_map)

def _parse_vppname_map(s, valregex, keyregex):
    """Find key and value in a string using regex.

    :param s:               String.
    :param valregex:        Value.
    :param keyregex:        Key.

    :returns: Error message and status code.
    """
    # get value
    r = re.search(valregex,s)
    if r!=None: val_data = r.group(1)
    else: return (None, None)   # val not found, don't add and return
    # get key
    r = re.search(keyregex,s)
    if r!=None: key_data = r.group(1)
    else: return (None, None)   # key not found, don't add and return
    # Return values
    return (key_data, val_data)

def pci_sub_file(fname):
    """Substitute a file with pci address to VPP names.

    :param fname:      File name.

    :returns: Error message and status code.
    """
    shif = _vppctl_read('show hardware-interfaces')
    shif_vmxnet3 = _vppctl_read('show vmxnet3')
    if shif == None or shif_vmxnet3 == None:
        return {'message':'Error reading interface info', 'ok':0}
    data = shif.splitlines()
    datav = shif_vmxnet3.splitlines()
    pci_map = {}
    for intf in _get_group_delimiter(data, r"^\w.*?\d"):
        # Contains data for a given interface
        ifdata = ''.join(intf)
        (k,v) = _parse_vppname_map(ifdata,
            valregex=r"^(\w[^\s]+)\s+\d+\s+(\w+)",
            keyregex=r"\s+pci:.*\saddress\s(.*?)\s")
        if k and v: pci_map[pci_addr_full(k)] = v
    for intf in _get_group_delimiter(datav, r"^Interface:\s\w.*?\d"):
        # Contains data for a given interface
        ifdata = '\n'.join(intf)
        (k,v) = _parse_vppname_map(ifdata,
            valregex=r"^Interface:\s(\w[^\s]+)\s+",
            keyregex=r"\s+PCI\sAddress:\s(.*)")
        if k and v: pci_map[pci_addr_full(k)] = v

    return _sub_file(fname, pci_map)

def gre_sub_file(fname):
    """Substitute a file with tunnels to VPP names.

    :param fname:      File name.

    :returns: Error message and status code.
    """
    shtun = _vppctl_read('show ipsec gre tunnel')
    if shtun == None:
        return {'message':'Error reading tunnel info', 'ok':0}
    data = shtun.splitlines()
    tres = {}
    for tunnel in _get_group_delimiter(data, r"^\[\d+\].*"):
        # Contains data for a given tunnel
        tunneldata = '\n'.join(tunnel)
        (k,v) = _parse_vppname_map(tunneldata,
                       valregex=r"^\[(\d+)\].*local-sa",
                       keyregex=r"^\[\d+\].*local-sa\s(\d+)\s")
        if k and v: tres["ipsec-gre-"+k] = "ipsec-gre" + v
    return _sub_file(fname, tres)

def stop_router():
    """Stop VPP and rebind Linux interfaces.

     :returns: Error message and status code.
     """
    dpdk_ifs = []
    dpdk.devices = {}
    dpdk.dpdk_drivers = ["igb_uio", "vfio-pci", "uio_pci_generic"]
    dpdk.check_modules()
    dpdk.get_nic_details()
    os.system('sudo systemctl stop vpp')
    os.system('sudo systemctl stop frr')
    for d,v in dpdk.devices.items():
        if "Driver_str" in v:
            if v["Driver_str"] in dpdk.dpdk_drivers:
                dpdk.unbind_one(v["Slot"], False)
                dpdk_ifs.append(d)
        elif "Module_str" != "":
            dpdk_ifs.append(d)
    # refresh nic_details
    dpdk.get_nic_details()
    for d in dpdk_ifs:
        drivers_unused = dpdk.devices[d]["Module_str"].split(',')
        #print ("Drivers unused=" + str(drivers_unused))
        for drv in drivers_unused:
            #print ("Driver=" + str(drv))
            if drv not in dpdk.dpdk_drivers:
                dpdk.bind_one(dpdk.devices[d]["Slot"], drv, False)
                break

    fwstats.update_state(False)
    return {'message':'Router stopped successfully', 'ok':1}

def connect_to_router():
    """Connect to VPP Python API.

     :returns: None.
     """
    fwglobals.g.router_api.vpp_api.connect()

def disconnect_from_router():
    """Disconnect from VPP Python API.

     :returns: None.
     """
    fwglobals.g.router_api.vpp_api.disconnect()

def reset_router_config():
    """Reset router config by cleaning DB and removing config files.

     :returns: None.
     """
    with FwDbRequests(fwglobals.g.SQLITE_DB_FILE) as db_requests:
        db_requests.clean()
    if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
        os.remove(fwglobals.g.ROUTER_STATE_FILE)
    if os.path.exists(fwglobals.g.FRR_OSPFD_FILE):
        os.remove(fwglobals.g.FRR_OSPFD_FILE)
    if os.path.exists(fwglobals.g.VPP_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.VPP_CONFIG_FILE_BACKUP, fwglobals.g.VPP_CONFIG_FILE)
    if os.path.exists(fwglobals.g.CONN_FAILURE_FILE):
        os.remove(fwglobals.g.CONN_FAILURE_FILE)

    reset_dhcpd()

def get_router_state():
    """Check if VPP is running.

     :returns: VPP state.
     """
    reason = ''
    if os.path.exists(fwglobals.g.ROUTER_STATE_FILE):
        state = 'failed'
        with open(fwglobals.g.ROUTER_STATE_FILE, 'r') as f:
            reason = f.read()
    elif vpp_pid():
        state = 'running'
    else:
        state = 'stopped'
    return (state, reason)

def get_router_config(full=False):
    """Get router configuration.

     :param full:         Return requests together with translated commands.

     :returns: Array of requests from DB.
     """
    def _dump_config_request(db_requests, key, full):
        (request, params) = db_requests.fetch_request(key)
        if full:
            return {'message': request, 'params': params, 'cmd_list': db_requests.fetch_cmd_list(key)}
        else:
            return {'message': request, 'params': params}

    with FwDbRequests(fwglobals.g.SQLITE_DB_FILE) as db_requests:
        cfg = []

        # Dump start-router request
        if full and 'start-router' in db_requests.db:
            cfg.append(_dump_config_request(db_requests, 'start-router', full))
        # Dump interfaces
        for key in db_requests.db:
            if re.match('add-interface', key):
                cfg.append(_dump_config_request(db_requests, key, full))
        # Dump routes
        for key in db_requests.db:
            if re.match('add-route', key):
                cfg.append(_dump_config_request(db_requests, key, full))
        # Dump tunnels
        for key in db_requests.db:
            if re.match('add-tunnel', key):
                cfg.append(_dump_config_request(db_requests, key, full))
        # Dump dhcp configuration
        for key in db_requests.db:
            if re.match('add-dhcp-config', key):
                cfg.append(_dump_config_request(db_requests, key, full))
        return cfg if len(cfg) > 0 else None

def print_router_config(full=False):
    """Print router configuration.

     :param full:         Return requests together with translated commands.

     :returns: None.
     """
    def _print_config_request(db_requests, key, full):
        (_, params) = db_requests.fetch_request(key)
        print("Key:\n   %s" % key)
        print("Request:\n   %s" % json.dumps(params, sort_keys=True, indent=4))
        if full:
            cmd_list = db_requests.fetch_cmd_list(key)
            print("Commands:\n  %s" % yaml_dump(cmd_list))
        print("")

    with FwDbRequests(fwglobals.g.SQLITE_DB_FILE) as db_requests:
        if 'start-router' in db_requests.db:
            print("======== START COMMAND =======")
            _print_config_request(db_requests, 'start-router', full)

        head_line_printed = False
        for key in db_requests.db:
            if re.match('add-interface', key):
                if not head_line_printed:
                    print("========= INTERFACES =========")
                    head_line_printed = True
                _print_config_request(db_requests, key, full)

        head_line_printed = False
        for key in db_requests.db:
            if re.match('add-route', key):
                if not head_line_printed:
                    print("=========== ROUTES ===========")
                    head_line_printed = True
                _print_config_request(db_requests, key, full)

        head_line_printed = False
        for key in db_requests.db:
            if re.match('add-tunnel', key):
                if not head_line_printed:
                    print("=========== TUNNELS ==========")
                    head_line_printed = True
                _print_config_request(db_requests, key, full)

        head_line_printed = False
        for key in db_requests.db:
            if re.match('add-dhcp-config', key):
                if not head_line_printed:
                    print("=========== DHCP CONFIG ==========")
                    head_line_printed = True
                _print_config_request(db_requests, key, full)

#
def _get_group_delimiter(lines, delimiter):
    """Helper function to iterate through a group lines by delimiter.

    :param lines:       List of text lines.
    :param delimiter:   Regex to group lines by.

    :returns: None.
    """
    data = []
    for line in lines:
        if re.match(delimiter,line)!=None:
            if data:
                yield data
                data = []
        data.append(line)
    if data:
        yield data

def _parse_add_if(s, res):
    """Helper function that parse fields from a given interface data and add to res.

    :param s:       String with interface data.
    :param res:     Dict to store the result in.

    :returns: None.
    """
    # get interface name
    r = re.search(r"^(\w[^\s]+)\s+\d+\s+(\w+)",s)
    if r!=None and r.group(2)=="up": if_name = r.group(1)
    else: return    # Interface not found, don't add and return
    # rx packets
    r = re.search(r" rx packets\s+(\d+)?",s)
    if r!=None: rx_pkts = r.group(1)
    else: rx_pkts = 0
    # tx packets
    r = re.search(r" tx packets\s+(\d+)?",s)
    if r!=None: tx_pkts = r.group(1)
    else: tx_pkts = 0
    # rx bytes
    r = re.search(r" rx bytes\s+(\d+)?",s)
    if r!=None: rx_bytes = r.group(1)
    else: rx_bytes = 0
    # tx bytes
    r = re.search(r" tx bytes\s+(\d+)?",s)
    if r!=None: tx_bytes = r.group(1)
    else: tx_bytes = 0
    # Add data to res
    res[if_name] = {'rx_pkts':long(rx_pkts), 'tx_pkts':long(tx_pkts), 'rx_bytes':long(rx_bytes), 'tx_bytes':long(tx_bytes)}

def get_vpp_if_count():
    """Get number of VPP interfaces.

     :returns: Dictionary with results.
     """
    shif = _vppctl_read('sh int', wait=False)
    if shif == None:  # Exit with an error
        return {'message':'Error reading interface info', 'ok':0}
    data = shif.splitlines()
    res = {}
    for intf in _get_group_delimiter(data, r"^\w.*?\s"):
        # Contains data for a given interface
        ifdata = ''.join(intf)
        _parse_add_if(ifdata, res)
    return {'message':res, 'ok':1}

def ip_str_to_bytes(ip_str):
    """Convert IP address string into bytes.

     :param ip_str:         IP address string.

     :returns: IP address in bytes representation.
     """
    # take care of possible netmask, like in 192.168.56.107/24
    addr_ip = ip_str.split('/')[0]
    addr_len = int(ip_str.split('/')[1]) if len(ip_str.split('/')) > 1 else 32
    return socket.inet_pton(socket.AF_INET, addr_ip), addr_len

def mac_str_to_bytes(mac_str):      # "08:00:27:fd:12:01" -> bytes
    """Convert MAC address string into bytes.

     :param mac_str:        MAC address string.

     :returns: MAC address in bytes representation.
     """
    return mac_str.replace(':', '').decode('hex')

def is_python2():
    """Checks if it is Python 2 version.

     :returns: 'True' if Python2 and 'False' otherwise.
     """
    ret = True if sys.version_info < (3, 0) else False
    return ret

def hex_str_to_bytes(hex_str):
    """Convert HEX string into bytes.

     :param hex_str:        HEX string.

     :returns: Bytes array.
     """
    if is_python2():
        return hex_str.decode("hex")
    else:
        return bytes.fromhex(hex_str)

def is_str(p):
    """Check if it is a string.

     :param p:          String.

     :returns: 'True' if string and 'False' otherwise.
     """
    if is_python2():
        return type(p)==str or type(p)==unicode
    else:
        return type(p)==str

def yaml_dump(var):
    """Convert object into YAML string.

    :param var:        Object.

    :returns: YAML string.
    """
    str = yaml.dump(var, canonical=True)
    str = re.sub(r"\n[ ]+: ", ' : ', str)
    return str

#
def valid_message_string(str):
    """Ensure that string contains only allowed by management characters.
    To mitigate security risks management limits text that might be received
    within responses to the management-to-device requests.
    This function ensure the compliance of string to the management requirements.

    :param str:        String.

    :returns: 'True' if valid and 'False' otherwise.
    """
    if len(str) > 200:
        fwglobals.log.excep("valid_message_string: string is too long")
        return False
    # Enable following characters only: [0-9],[a-z],[A-Z],'-','_',' ','.',':',',', etc.
    tmp_str = re.sub(r'[-_.,:0-9a-zA-Z_" \']', '', str)
    if len(tmp_str) > 0:
        fwglobals.log.excep("valid_message_string: string has not allowed characters")
        return False
    return True

def obj_dump(obj, print_obj_dir=False):
    """Print object fields and values. Used for debugging.

     :param obj:                Object.
     :param print_obj_dir:      Print list of attributes and methods.

     :returns: None.
     """
    callers_local_vars = inspect.currentframe().f_back.f_locals.items()
    obj_name = [var_name for var_name, var_val in callers_local_vars if var_val is obj][0]
    print('========================== obj_dump start ==========================')
    print("obj=%s" % obj_name)
    print("str(%s): %s" % (obj_name, str(obj)))
    if print_obj_dir:
        print("dir(%s): %s" % (obj_name, str(dir(obj))))
    obj_dump_attributes(obj)
    print('========================== obj_dump end ==========================')

def obj_dump_attributes(obj, level=1):
    """Print object attributes.

    :param obj:          Object.
    :param level:        How many levels to print.

    :returns: None.
    """
    for a in dir(obj):
        if re.match('__.+__', a):   # Escape all special attributes, like __abstractmethods__, for which val = getattr(obj, a) might fail
            continue
        val = getattr(obj, a)
        if isinstance(val, (int, float, str, unicode, list, dict, set, tuple)):
            print(level*' ' + a + '(%s): ' % str(type(val)) + str(val))
        else:
            print(level*' ' + a + ':')
            obj_dump_attributes(val, level=level+1)

def vpp_startup_conf_update(filename, path, param, val, add, filename_backup=None):
    """Updates the /etc/vpp/startup.conf

    :param filename:    /etc/vpp/startup.conf
    :param path:        path to parameter in the startup.conf, e.g. 'dpdk/dev 0000:02:00.1'
    :param param:       name of the parameter, e.g. 'name'
    :param val:         value of the paremeter, e.g. 'eth0'
    :param add:         if True the parameter will be added or modified,
                        if False the parameter will be commented out

     :returns: None.
     """

    # Load file into dictionary
    conf = fwtool_vpp_startupconf_dict.load(filename)

    # Goto the leaf sub-section according the path.
    # If some of sections don't exist, create them.
    # Section is a list that might contains parameters (list) or sub-sections (dictionaries),
    # so steps in path stands for dictionaries, when the last step is list.
    section = conf
    steps = path.split('/')
    prev_section = section
    prev_step    = steps[0]
    for (idx, step) in enumerate(steps):
        if step not in section:
            if idx < len(steps)-1:
                section[step] = {}
            else:
                section[step] = []  # Last step which is list
        prev_section = section
        prev_step    = step
        section      = section[step]

    # If leaf section is empty (it is possible if path exists, but section is empty)
    # initialize it with empty list of parameters.
    if section is None:
        prev_section[prev_step] = []
        section = prev_section[prev_step]

    # Update parameter.
    # Firstly find it in section list of parameter
    found_elements = [ el for el in section if param in el ]
    if add:
        # If element was found, update it. Otherwise - add new parameter
        if len(found_elements) > 0:
            if not val is None:     # If there is a value to update ...
                found_elements[0][param] = val
        else:
            if val is None:
                section.append(param)
            else:
                section.append({param: val})
    else:
        if len(found_elements) > 0:
            section.remove(found_elements[0])
            section.append('ELEMENT_TO_BE_REMOVED')
        if len(section) == 0:
            prev_section[prev_step] = None

    # Dump dictionary back into file
    fwtool_vpp_startupconf_dict.dump(conf, filename)

def vpp_startup_conf_add_devices(params):
    filename = params['vpp_config_filename']
    config   = fwtool_vpp_startupconf_dict.load(filename)

    if not config.get('dpdk'):
        config['dpdk'] = []
    for dev in params['devices']:
        config_param = 'dev %s' % dev
        if not config_param in config['dpdk']:
            config['dpdk'].append(config_param)

    fwtool_vpp_startupconf_dict.dump(config, filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_remove_devices(params):
    filename = params['vpp_config_filename']
    config   = fwtool_vpp_startupconf_dict.load(filename)

    if not config.get('dpdk'):
        return
    for dev in params['devices']:
        config_param = 'dev %s' % dev
        if config_param in config['dpdk']:
            config['dpdk'].remove(config_param)
    if len(config['dpdk']) == 0:
        config['dpdk'].append('ELEMENT_TO_BE_REMOVED')  # Need this to avoid empty list section before dump(), as yaml goes crazy with empty list sections

    fwtool_vpp_startupconf_dict.dump(config, filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_add_nat(params):
    filename = params['vpp_config_filename']
    config   = fwtool_vpp_startupconf_dict.load(filename)
    config['nat'] = []
    config['nat'].append('endpoint-dependent')
    config['nat'].append('translation hash buckets 1048576')
    config['nat'].append('translation hash memory 268435456')
    config['nat'].append('user hash buckets 1024')
    config['nat'].append('max translations per user 10000')
    fwtool_vpp_startupconf_dict.dump(config, filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def vpp_startup_conf_remove_nat(params):
    filename = params['vpp_config_filename']
    config   = fwtool_vpp_startupconf_dict.load(filename)
    if config.get('nat'):
        del config['nat']
    fwtool_vpp_startupconf_dict.dump(config, filename)
    return (True, None)   # 'True' stands for success, 'None' - for the returned object or error string.

def _get_interface_address(pci):
    """ Get interface ip address from commands DB.
    """
    for key, request in fwglobals.g.router_api.db_requests.db.items():

        if not re.search('add-interface', key):
            continue
        if request['params']['pci'] != pci:
            continue
        addr = request['params']['addr']
        return addr

    return None

def reset_dhcpd():
    if os.path.exists(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP, fwglobals.g.DHCPD_CONFIG_FILE)

    cmd = 'sudo systemctl stop isc-dhcp-server'

    try:
        output = subprocess.check_output(cmd, shell=True)
    except:
        return False

    return True

def modify_dhcpd(params):
    """Modify /etc/dhcp/dhcpd configuration file.

    :param params:   Parameters from flexiManage.

    :returns: String with sed commands.
    """
    pci = params['params']['interface']
    range_start = params['params'].get('range_start', '')
    range_end = params['params'].get('range_end', '')
    dns = params['params'].get('dns', {})
    mac_assign = params['params'].get('mac_assign', {})
    is_add = params['params']['is_add']

    address = IPNetwork(_get_interface_address(pci))
    router = str(address.ip)
    subnet = str(address.network)
    netmask = str(address.netmask)

    if not os.path.exists(fwglobals.g.DHCPD_CONFIG_FILE_BACKUP):
        shutil.copyfile(fwglobals.g.DHCPD_CONFIG_FILE, fwglobals.g.DHCPD_CONFIG_FILE_BACKUP)

    config_file = fwglobals.g.DHCPD_CONFIG_FILE

    remove_string = 'sudo sed -e "/subnet %s netmask %s {/,/}/d" ' \
                    '-i %s; ' % (subnet, netmask, config_file)

    range_string = ''
    if range_start:
        range_string = 'range %s %s;\n' % (range_start, range_end)

    if dns:
        dns_string = 'option domain-name-servers'
        for d in dns[:-1]:
            dns_string += ' %s,' % d
        dns_string += ' %s;\n' % dns[-1]
    else:
        dns_string = ''

    subnet_string = 'subnet %s netmask %s' % (subnet, netmask)
    routers_string = 'option routers %s;\n' % (router)
    dhcp_string = 'echo "' + subnet_string + ' {\n' + range_string + \
                 routers_string + dns_string + '}"' + ' | sudo tee -a %s;' % config_file

    if is_add == 1:
        exec_string = remove_string + dhcp_string
    else:
        exec_string = remove_string

    for mac in mac_assign:
        remove_string_2 = 'sudo sed -e "/host %s {/,/}/d" ' \
                          '-i %s; ' % (mac['host'], config_file)

        host_string = 'host %s {\n' % (mac['host'])
        ethernet_string = 'hardware ethernet %s;\n' % (mac['mac'])
        ip_address_string = 'fixed-address %s;\n' % (mac['ipv4'])
        mac_assign_string = 'echo "' + host_string + ethernet_string + ip_address_string + \
                            '}"' + ' | sudo tee -a %s;' % config_file

        if is_add == 1:
            exec_string += remove_string_2 + mac_assign_string
        else:
            exec_string += remove_string_2

    try:
        output = subprocess.check_output(exec_string, shell=True)
    except:
        return (False, None)

    return (True, None)
