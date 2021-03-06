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

import threading
import uuid
import fwglobals
import fwagent
import random
import time
import json
import websocket
import fwutils
import ssl
import fwagent
import traceback
import sys
import fwstats

class LoadSimulator:
    """This is a load simulator class.
       It is used to emulate a big number of fake devices.
    """
    def __init__(self):
        """Constructor method
        """
        self.simulate_mode = 0
        self.simulate_count = 1
        self.simulate_id = 0
        self.simulate_device_tokens = []
        self.simulate_threads = {}
        self.simulate_websockets = {}
        self.started = True
        self.simulate_event = threading.Event()
        self.machine_ids = []
        self.simulate_stats = {'tx_pkts': 0, 'tx_bytes': 0, 'rx_bytes': 0, 'rx_pkts': 0}
        self.simulate_tunnel_stats = {"1": {"status": "up", "rtt": 10, "drop_rate": 0}}
        self.interface_wan = 'GigabitEthernet0/8/0'
        self.interface_lan = 'GigabitEthernet0/3/0'
        self.data = ''
        self.version = fwutils.get_agent_version(fwglobals.g.VERSIONS_FILE)
        self.thread_statistics = None

    def stop(self):
        """Stop simulated devices.

        :returns: None.
        """
        self.started = False
        for ws in self.simulate_websockets.values():
            ws.keep_running = False

    def enable(self, count):
        """Enable simulation.

        :param count:         Number of fake devices.

        :returns: None.
        """
        self.simulate_mode = 1
        self.simulate_count = count

    def enabled(self):
        """Check if simulation is enabled.

        :returns: 'True' in case if enabled.
        """
        return self.simulate_mode == 1

    def count(self):
        """Get number of fake devices.

        :returns: Number of devices.
        """
        return self.simulate_count

    def generate_machine_id(self):
        """Generate UUID.

        :returns: None.
        """
        self.machine_ids.append(str(uuid.uuid1()))

    def get_generated_machine_id(self, i):
        """Get UUID.

        :returns: UUID.
        """
        return self.machine_ids[i]

    def connect(self):
        """Connect a device using websocket.

        :returns: `True` if connection was successful, `False` otherwise.
        """
        self.data = json.loads(self.simulate_device_tokens[self.simulate_id])

        machine_id = self.get_generated_machine_id(self.simulate_id)
        fwglobals.log.info("connecting to flexiWAN orchestrator with uuid %s" % machine_id)

        url = "wss://%s/%s?token=%s" % (self.data['server'], machine_id, self.data['deviceToken'])
        header_UserAgent = "User-Agent: fwagent/%s" % (self.version)

        self.simulate_threads[self.simulate_id] = threading.Thread(target=fwagent.Fwagent().websocket_thread,
                                             name='Websocket Thread ' + str(self.simulate_id),
                                             args=(url, header_UserAgent, self.simulate_id))
        self.simulate_threads[self.simulate_id].start()

        self.simulate_event.wait()
        self.simulate_event.clear()

        return True

    def simulate(self, count):
        """Simulate command line argument handler.

        :param count:         Number of fake devices.

        :returns: None.
        """
        fwglobals.log.info("started in simulate mode")

        with fwagent.Fwagent() as agent:

            self.enable(int(count))

            # Generate temporary machine IDs
            # -------------------------------------
            for self.simulate_id in range(self.count()):
                self.generate_machine_id()
                if not self.started:
                    break

                # Register with Manager
                # -------------------------------------
                while not agent.register() and self.started:
                    retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
                    fwglobals.log.info("retry registration in %d seconds" % retry_sec)
                    time.sleep(retry_sec)

            self.simulate_id = 0
            for self.simulate_id in range(self.count()):
                # Establish main connection to Manager
                # and start infinite receive-send loop.
                # -------------------------------------
                if not self.started:
                    break
                self.connect()

            while self.started is True:
                time.sleep(1)

    def update_stats(self):
        """Update fake statistics.

        :returns: None.
        """
        self.simulate_stats['tx_pkts'] += 10
        self.simulate_stats['tx_bytes'] += 1000
        self.simulate_stats['rx_bytes'] += 2000
        self.simulate_stats['rx_pkts'] += 20

        new_stats = {'ok': 1,
                     'message': {self.interface_wan: dict(self.simulate_stats),
                                 self.interface_lan: dict(self.simulate_stats)}}

        if new_stats['ok'] == 1:
            prev_stats = dict(fwstats.stats)  # copy of prev stats
            fwstats.stats['time'] = time.time()
            fwstats.stats['last'] = new_stats['message']
            fwstats.stats['ok'] = 1
            # Update info if previous stats valid
            if prev_stats['ok'] == 1:
                if_bytes = {}
                for intf, counts in fwstats.stats['last'].items():
                    prev_stats_if = prev_stats['last'].get(intf, None)
                    if prev_stats_if != None:
                        rx_bytes = 1.0 * (counts['rx_bytes'] - prev_stats_if['rx_bytes'])
                        rx_pkts = 1.0 * (counts['rx_pkts'] - prev_stats_if['rx_pkts'])
                        tx_bytes = 1.0 * (counts['tx_bytes'] - prev_stats_if['tx_bytes'])
                        tx_pkts = 1.0 * (counts['tx_pkts'] - prev_stats_if['tx_pkts'])
                        if_bytes[intf] = {
                            'rx_bytes': rx_bytes,
                            'rx_pkts': rx_pkts,
                            'tx_bytes': tx_bytes,
                            'tx_pkts': tx_pkts
                        }

                fwstats.stats['bytes'] = if_bytes
                fwstats.stats['tunnel_stats'] = self.simulate_tunnel_stats
                fwstats.stats['period'] = fwstats.stats['time'] - prev_stats['time']
                fwstats.stats['running'] = True
        else:
            fwstats.stats['ok'] = 0

        # Add the update to the list of updates. If the list is full,
        # remove the oldest update before pushing the new one
        if len(fwstats.updates_list) is fwstats.UPDATE_LIST_MAX_SIZE:
            fwstats.updates_list.pop(0)

        fwstats.updates_list.append({
            'ok': fwstats.stats['ok'],
            'running': fwstats.stats['running'],
            'stats': fwstats.stats['bytes'],
            'period': fwstats.stats['period'],
            'tunnel_stats': fwstats.stats['tunnel_stats'],
            'utc': time.time()
        })

def initialize():
    """Initialize a singleton.

    :returns: None.
    """
    global g
    g = LoadSimulator()

def is_initialized():
    """Check if singleton is initialized.

    :returns: 'True' if singleton is initialized and 'False' otherwise.
    """
    return 'g' in globals()
