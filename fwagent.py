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

import json
import os


# Try with PY3 else, use PY2
try:
    from urllib import request as ureq
    from urllib import parse as uparse
    from urllib import error as uerr
    from http import server as hsvr
    raw_input = input   # Python 2 has raw_input, and it doesn't support function aliasing, so downgrade :)
except ImportError:
    import urllib2 as ureq
    import urllib as uparse
    import urllib2 as uerr
    import BaseHTTPServer as hsvr

import websocket
import ssl
import socket
import sys
import time
import random
import signal
import psutil
import Pyro4
import re
import subprocess
import threading
import traceback
import yaml
import fwglobals
import fwstats
import fwutils
from fwlog import Fwlog
import loadsimulator

# Global signal handler for clean exit
def global_signal_handler(signum, frame):
    """Global signal handler for CTRL+C

    :param signum:         Signal type
    :param frame:          Stack frame.

    :returns: None.
    """
    exit(1)

signal.signal(signal.SIGINT, global_signal_handler)

class Fwagent:
    """This class implements abstraction of mediator between manager called
    flexiManage and device called flexiEdge. The manager runs on remote server,
    the Fwagent runs on device. The Fwagent establishes protected connection
    to the manager and starts infinite message handling loop. It receives
    message, called request, invokes global message handler that routes
    the request to the appropriate request handler, takes response
    returned by the message handler and sends it back to the manager.
    Only one request can be processed at any time.
    The global message handler sits in the Fwglobals module.

    :param handle_sigterm: A flag to handle termination signal
    """
    def __init__(self, handle_sigterm=True):
        """Constructor method
        """
        fwglobals.g.initialize()
        self.token                = None
        self.version              = fwutils.get_agent_version(fwglobals.g.VERSIONS_FILE)
        self.ws                   = None
        self.thread_statistics    = None
        self.should_reconnect     = False
        self.pending_msg_replies  = []

        if handle_sigterm:
            signal.signal(signal.SIGTERM, self._sigterm_handler)

        if loadsimulator.is_initialized():
            signal.signal(signal.SIGINT, self._sigint_handler)

    def _sigint_handler(self, signum, frame):
        """Signal handler for CTRL+C

        :param signum:         Signal type
        :param frame:          Stack frame.

        :returns: None.
        """
        fwglobals.log.info("Fwagent got SIGINT")
        loadsimulator.g.stop()
        self.__exit__(None, None, None)
        exit(1)

    def _sigterm_handler(self, signum, frame):
        """Signal handler for SIGTERM signal

        :param signum:         Signal type
        :param frame:          Stack frame.

        :returns: None.
        """
        fwglobals.log.info("Fwagent got SIGTERM")
        self.__exit__(None, None, None)
        exit(1)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        self._clean_on_exit()
        fwglobals.g.finalize()

    def _clean_on_exit(self):
        # Close connection
        if self.ws:
            self.ws.close()
        # Stop threads
        if self.thread_statistics:
            self.thread_statistics.join()

    def _mark_connection_failure(self, err):
        try:
            with open(fwglobals.g.CONN_FAILURE_FILE, 'w') as stream:
                stream.write('Failed to connect to MGMT: %s' % err)
                fwglobals.log.debug("_mark_connection_failure: %s" % str(err))
        except Exception as e:
            fwglobals.log.excep("Failed to create connection failure file: %s" % str(e))

    def _clean_connection_failure(self):
        if os.path.exists(fwglobals.g.CONN_FAILURE_FILE):
            os.remove(fwglobals.g.CONN_FAILURE_FILE)
            fwglobals.log.debug("_clean_connection_failure")

    def register(self):
        """Registers device with the flexiManage.
        To do that the Fwagent establishes secure HTTP connection to the manager
        and sends GET request with various data regarding device.
        When user approves device on manager, the Fwagent establishes secure
        WebSocket connection to the manager and starts to listen for flexiManage
        requests.

        :returns: `True` if registration succeeded, `False` otherwise.
        """

        fwglobals.log.info("registering with flexiWAN orchestrator...")

        self.register_error = ''

        if not loadsimulator.g.enabled():
            if os.path.exists(fwglobals.g.DEVICE_TOKEN_FILE):
                fwglobals.log.info("register: already registered, to refresh run 'fwagent reset' and retry")
                return True

        try:
            with open(fwglobals.g.cfg.TOKEN_FILE, 'r') as f:
                self.token = f.readline()
        except:
            err = "register: failed to load token from %s: %s (%s)" % \
                (fwglobals.g.cfg.TOKEN_FILE, format(sys.exc_info()[1]),  format(sys.exc_info()[0]))
            fwglobals.log.error(err)
            return False

        if fwutils.vpp_does_run():
            fwglobals.log.error("register: router is running, it by 'fwagent stop' and retry by 'fwagent start'")
            return False

        if loadsimulator.g.enabled():
            machine_id = loadsimulator.g.get_generated_machine_id(loadsimulator.g.simulate_id)
        else:
            machine_id = fwutils.get_machine_id()
        if machine_id == None:
            fwglobals.log.error("register: get_machine_id failed, make sure you're running in sudo privileges")
            return False

        machine_name = socket.gethostname()
        all_ip_list = socket.gethostbyname_ex(machine_name)[2]
        interfaces = fwglobals.g.handle_request('interfaces')
        default_route = fwutils.get_default_route()
        # get up to 4 IPs
        ip_list = ', '.join(all_ip_list[0:min(4,len(all_ip_list))])
        url = fwglobals.g.cfg.MANAGEMENT_URL  + "/api/connect/register"

        data = uparse.urlencode({'token': self.token.rstrip(),
                                'fwagent_version' : self.version,
                                'machine_id' : machine_id,
                                'machine_name': machine_name,
                                'ip_list': ip_list,
                                'default_route': default_route[0],
                                'default_dev': default_route[1],
                                'interfaces': json.dumps(interfaces['message'])}).encode()
        req = ureq.Request(url, data)
        ctx = ssl.create_default_context()
        if fwglobals.g.cfg.BYPASS_CERT:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED

        try:
            resp = ureq.urlopen(req, context=ctx)
            data = resp.read().decode()
            if loadsimulator.g.enabled():
                loadsimulator.g.simulate_device_tokens.append(data)
            else:
                with open(fwglobals.g.DEVICE_TOKEN_FILE, 'w') as fout:
                    fout.write(data)
            fwglobals.log.info("Registation successful with parameters:")
            fwglobals.log.info("  Hostname:  " + machine_name)
            fwglobals.log.info("  IP List:   " + ip_list)
            fwglobals.log.info("  Device ID: " + machine_id)
            fwglobals.log.info("Run connect after approving device in the orchestrator")

        except uerr.URLError as e:
            if hasattr(e, 'code'):
                server_response = e.read().decode()
                fwglobals.log.error('register: got %s - %s' % (str(e.code), hsvr.BaseHTTPRequestHandler.responses[e.code][0]))
                fwglobals.log.error('register: Server response: %s' % server_response)
                try:
                    register_response = json.loads(server_response)
                    if 'error' in register_response:
                        self.register_error = register_response['error'].lower()
                except:
                    pass
            elif hasattr(e, 'reason'):
                fwglobals.log.error('register: failed to connect to %s: %s' % (fwglobals.g.cfg.MANAGEMENT_URL, e.reason))
            return False
        except:
            fwglobals.log.error('register: failed to send request to server %s: %s' % \
                        (fwglobals.g.cfg.MANAGEMENT_URL, format(sys.exc_info()[1])))
            return False
        return True

    def websocket_thread(self, url, header_UserAgent, id):
        """This is thread that creates WebSocket connection.
        Fwagent uses only one connection at any given moment.
        Multiple connections are used by load simulator (loadsimulator.py).

        :param url:                 URL
        :param header_UserAgent:    UserAgent HTML header contents.
        :param id:                  Device UUID.

        :returns: None.
        """

        # WebSocket callbacks
        def on_open(ws):
            self._on_open(ws)
        def on_message(ws, message):
            self._on_message(ws, message)
        def on_error(ws, error):
            self._on_error(ws, error)
        def on_close(ws):
            self._on_close(ws)

        while loadsimulator.g.started:
            loadsimulator.g.simulate_websockets[id] = websocket.WebSocketApp(url,
                                                                            header={header_UserAgent},
                                                                            on_open=on_open,
                                                                            on_message=on_message,
                                                                            on_error=on_error,
                                                                            on_close=on_close)

            cert_required = ssl.CERT_NONE if fwglobals.g.cfg.BYPASS_CERT else ssl.CERT_REQUIRED

            loadsimulator.g.simulate_websockets[id].run_forever(sslopt={"cert_reqs": cert_required},
                                                                ping_interval=25, ping_timeout=20)
            retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
            fwglobals.log.info("websocket_thread %d: retry connection in %d seconds" % (id, retry_sec))
            time.sleep(retry_sec)

    def connect(self):
        """Establishes the main WebSocket connection between device and manager,
        on which Fwagent receives manager requests.

        :returns: `True` if connection was established, `False` otherwise.
        """
        fwglobals.log.info("connecting to flexiWAN orchestrator...")

        self.connection_error_code = 0

        # Load device token obtained during registration
        device_token_fname = fwglobals.g.DEVICE_TOKEN_FILE
        if not os.path.exists(device_token_fname):
            fwglobals.log.error("connect: device token not found (" + device_token_fname + "), please register first")
            return False
        try:
            with open(device_token_fname, 'r') as fin:
                    fdata = fin.readline()
                    self.data = json.loads(fdata)
        except:
            fwglobals.log.error("connect: failed to load device token from " + device_token_fname + ": " + format())
            return False

        # WebSocket callbacks
        def on_open(ws):
            self._on_open(ws)
        def on_message(ws, message):
            self._on_message(ws, message)
        def on_error(ws, error):
            self._on_error(ws, error)
        def on_close(ws):
            self._on_close(ws)

        # Remove WebSocket send/recv message prints to STDOUT until proper logging configuration is implemented
        #websocket.enableTrace(fwglobals.g.cfg.DEBUG)

        machine_id = fwutils.get_machine_id()
        if machine_id == None:
            fwglobals.log.error("connect: can't connect (failed to retrieve machine ID in fwutils.py:get_machine_id")
            return False
        url = "wss://%s/%s?token=%s" % (self.data['server'], machine_id, self.data['deviceToken'])
        header_UserAgent = "User-Agent: fwagent/%s" % (self.version)

        self.ws = websocket.WebSocketApp(url,
                                    header     = {header_UserAgent},
                                    on_open    = on_open,
                                    on_message = on_message,
                                    on_error   = on_error,
                                    on_close   = on_close)
        self.connection_error_code = 0

        cert_required = ssl.CERT_NONE if fwglobals.g.cfg.BYPASS_CERT else ssl.CERT_REQUIRED

        self.ws.run_forever(sslopt={"cert_reqs": cert_required}, ping_interval=0)
		# DON'T USE ping_interval, ping_timeout !!!
		# They might postpone ws.close()/ws.close(timeout=X) for ping_interval!
		# That my stuck 'fwagent stop'/'systemtctl restart', where we clean resources on exit.
		# We use application level keep-alive, so no need in WebSocket ping-pong.
        #self.ws.run_forever(sslopt={"cert_reqs": cert_required},
        #                    ping_interval=0, ping_timeout=0)
        if self.connection_error_code:
            return False
        return True

    def _on_error(self, ws, error):
        """Handles WebSocket connection errors either local errors, like name
        resolution failure, network errors like TCP timeout or WebSocket
        handshake rejects sent by manager.

        :param ws:       Websocket handler.
        :param error:    Error instance.

        :returns: None.
        """
        if 'status_code' in dir(error):
            self.connection_error_code = error.status_code
            self.connection_error_msg  = "not approved" \
                if error.status_code == fwglobals.g.WS_STATUS_CODE_NOT_APPROVED \
                else str(error)
        else:
            self.connection_error_code = fwglobals.g.WS_STATUS_LOCAL_ERROR
            self.connection_error_msg  = str(error)
        fwglobals.log.error("connection got error: " + self.connection_error_msg)

        # Create a file to signal the upgrade process that the
        # upgraded agent failed to connect to the management.
        self._mark_connection_failure(self.connection_error_msg)

        ws.close()

    def _on_close(self, ws):
        """Websocket connection close handler

        :param ws:  Websocket handler.

        :returns: None.
        """
        fwglobals.log.info("connection to orchestrator is closed")
        if self.thread_statistics:
            self.isConnRunning = False
            self.thread_statistics.join()

    def _on_open(self, ws):
        """Websocket connection open handler

        :param ws:  Websocket handler.

        :returns: None.
        """
        self._clean_connection_failure()

        if loadsimulator.g.enabled():
            loadsimulator.g.simulate_event.set()

        # Send pending message replies to the MGMT upon connection reopen.
        # These are replies to messages that might have cause the connection
        # to the MGMT to disconnect, and thus have to be sent on the new connection.
        if len(self.pending_msg_replies) > 0:
            fwglobals.log.info("_on_open: sending %d pending replies to orchestrator" % len(self.pending_msg_replies))
            for reply in self.pending_msg_replies:
                fwglobals.log.debug("_on_open: sending reply: " + json.dumps(reply))
                ws.send(json.dumps(reply))

            del self.pending_msg_replies[:]

        def run(*args):
            slept = 0
            while self.isConnRunning:
                # Every 30 seconds ensure that connection to management is alive.
                # Management should send 'get-device-stats' request every 10 sec.
                # Note the WebSocket Ping-Pong (see ping_interval=25, ping_timeout=20)
                # does not help in case of Proxy in the middle, as was observed in field
                if (slept % 30) == 0:
                    if self.requestReceived:
                        self.requestReceived = False
                    else:
                        fwglobals.log.debug("connect: no request was received in 30 seconds, drop connection")
                        ws.close()
                        fwglobals.log.debug("connect: connection was terminated")
                        break
                # Every 30 seconds update statistics
                if (slept % 30) == 0:
                    if loadsimulator.g.enabled():
                        if loadsimulator.g.started:
                            loadsimulator.g.update_stats()
                        else:
                            break
                    else:
                        fwstats.update_stats()
                # Sleep 1 second and make another iteration
                time.sleep(1)
                slept += 1

        self.isConnRunning = True
        self.requestReceived = True
        self.thread_statistics = threading.Thread(target=run, name='Statistics Thread')
        self.thread_statistics.start()

        if not fwutils.vpp_does_run():
            fwglobals.log.info("connect: router is not running, start it in orchestrator")


    def _on_message(self, ws, message):
        """Websocket received message handler.
        This callbacks invokes global handler of the received request defined
        in the fwglobals.py module, gets back the response from the global
        handler and sends it back to the server. The global handler dispatches
        requests to appropriate request handlers. It is implemented
        in the fwglobals.py module.

        :param ws:       Websocket handler.
        :param message:  Message instance.

        :returns: None.
        """
        pmsg = json.loads(message)
        msg = pmsg['msg']

        reply = self.handle_received_request(msg)

        fwglobals.log.debug(str(pmsg['seq']) + " request=" + message)
        fwglobals.log.debug(str(pmsg['seq']) + " reply=" + json.dumps(reply))

        # Messages that change the interfaces might cause the existing connection to break
        # (for example, if the IP/mask has changed). Since sending the reply on a broken
        # connection will not work, we close the connection and save the reply for later.
        # when the new connection is opened, we send the reply to the MGMT right away.
        # We close the connection even if the request failed, as the change might have
        # taken place regardless of the request status, hence socket might not be operational.
        self.should_reconnect = False if 'params' not in msg else msg['params'].get('reconnect', False)
        if self.should_reconnect == True:
            fwglobals.log.info("_on_message: device changed, closing connection to orchestrator")
            self.pending_msg_replies.append({'seq':pmsg['seq'], 'msg':reply})
            self.connection_error_code = fwglobals.g.WS_STATUS_DEVICE_CHANGE
            self.connection_error_msg = 'device change'
            ws.close()
        else:
            ws.send(json.dumps({'seq':pmsg['seq'], 'msg':reply}))

    def disconnect(self):
        """Shutdowns the WebSocket connection.

        :returns: None.
        """
        if self.ws:
            self.ws.close()

    def handle_received_request(self, msg):
        """Handles received request: invokes the global request handler
        while logging the request and the response returned by the global
        request handler. Note the global request handler is implemented
        in the fwglobals.py module. It dispatches requests to the appropriate
        request handlers.

        :param msg:  Message instance.

        :returns: None.
        """
        print_message = fwglobals.g.cfg.DEBUG
        print_message = False if msg['message'] == 'get-device-stats' else print_message
        if print_message:
            fwglobals.log.debug("handle_received_request:request\n" + json.dumps(msg, sort_keys=True, indent=4))

        self.requestReceived = True

        reply = fwglobals.g.handle_request(msg['message'], msg.get('params'))

        if not 'entity' in reply and 'entity' in msg:
            reply.update({'entity':msg['entity']+'Reply'})
        if not 'message' in reply:
            reply.update({'message': 'success'})

        if print_message:
            fwglobals.log.debug("handle_received_request:reply\n" + json.dumps(reply, sort_keys=True, indent=4))
        return reply

def version():
    """Handles 'fwagent version' command.

    :returns: None.
    """
    with open(fwglobals.g.VERSIONS_FILE, 'r') as stream:
        versions = yaml.load(stream, Loader=yaml.BaseLoader)

        # Find the longest name of component
        width = 0
        for component in versions['components']:
            if len(component) > width:
                width = len(component)
        delimiter = '-' * (width + 10)

        print(delimiter)
        print('Device %s' % versions['device'])
        print(delimiter)
        for component in sorted(versions['components'].keys()):
            print('%s %s' % (component.ljust(width), versions['components'][component]['version']))
        print(delimiter)

def register():
    """Handles 'fwagent register' command.
    This command is not used in production.
    It stays with us for historical reasons and can be used for unit testing.

    :returns: None.
    """
    with Fwagent() as agent:
        agent.register()

def connect():
    """Handles 'fwagent connect' command.
    This command is not used in production.
    It stays with us for historical reasons and can be used for unit testing.

    :returns: None.
    """
    with Fwagent() as agent:
        for _ in range(fwglobals.g.NUM_RETRIES_ALLOWED):
            agent.connect()
            retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
            fwglobals.log.info("retry connection in %d seconds" % retry_sec)
            time.sleep(retry_sec)

def reset(soft):
    """Handles 'fwagent reset' command.
    Resets device to the initial state. Once reset, the device MUST go through
    the registration procedure.

    :param soft:  Soft reset: resets router configuration only.
                  No re-registration is needed.

    :returns: None.
    """
    daemon_rpc('stop')          # Stop daemon main loop if daemon is alive

    fwutils.reset_router_config()
    if soft:
        daemon_rpc('start')     # Start daemon main loop if daemon is alive
        return

    CSTART = "\x1b[0;30;43m"
    CEND = "\x1b[0m"
    choice = raw_input(CSTART + "Device must be deleted from the orchestrator before resetting the agent. " +
                      "Already deleted from orchestrator y/n [n]" + CEND)
    if choice == 'y':
        if os.path.exists(fwglobals.g.DEVICE_TOKEN_FILE):
            os.remove(fwglobals.g.DEVICE_TOKEN_FILE)
        fwglobals.log.info("Done")
    else:
        fwglobals.log.info("Reset operation aborted")
    daemon_rpc('start')     # Start daemon main loop if daemon is alive

def stop(reset_router_config, stop_router):
    """Handles 'fwagent stop' command.
    Stops the infinite connection loop run by Fwagent in daemon mode.
    See documentation on FwagentDaemon class.

    :param reset_router_config:  Reset router configuration.
    :param stop_router:          Stop router, thus disabling packet routing.

    :returns: None.
    """
    fwglobals.log.info("stopping router...")
    try:
        if stop_router==False:
            # if daemon runs, stop connection loop only, don't stop vpp
            daemon_rpc('stop', stop_vpp=False)
            fwglobals.log.info("done")
            return
        else:
            # if daemon runs, stop connection loop, stop vpp
            # and continue to fwutils.stop_router
            daemon_rpc('stop', stop_vpp=True)
    except:
        # Continue and stop vpp from shell and get interfaces back to Linux
        pass

    # To be on safe side call fwutils.stop_router() as well to
    # ensure interfaces are released back to Linux
    fwutils.stop_router()
    if reset_router_config:
        fwutils.reset_router_config()
    fwglobals.log.info("done")

def start(start_router):
    """Handles 'fwagent start' command.
    Starts the infinite connection loop run by Fwagent in daemon mode.
    See documentation on FwagentDaemon class.

    :param start_router:  Start router, while applying router configuration.

    :returns: None.
    """
    fwglobals.log.info("start router...")
    daemon_rpc('start', start_vpp=start_router) # if daemon runs, start connection loop and router if required
    fwglobals.log.info("done")

def show(agent_info, router_info):
    """Handles 'fwagent show' command.
    This commands prints various information about device and it's components,
    like router configuration, software version, etc.
    For full list of available options to show use 'fwagent --help'.

    :param agent_info:   Agent information.
    :param router_info:  Router information.

    :returns: None.
    """
    if agent_info:
        if agent_info == 'version':
            fwglobals.log.info('Agent version: %s' % fwutils.get_agent_version(fwglobals.g.VERSIONS_FILE), to_syslog=False)
    if router_info:
        if router_info == 'state':
            fwglobals.log.info('Router state: %s (%s)' % (fwutils.get_router_state()[0], fwutils.get_router_state()[1]))
        elif router_info == 'configuration':
            fwutils.print_router_config()
        elif router_info == 'request_db':
            fwutils.print_router_config(full=True)

@Pyro4.expose
class FwagentDaemon(object):
    """This class implements abstraction of Fwagent that runs in daemon mode.
    When the Fwagent runs as a daemon, someone has to create it and to invoke
    registration, connection and other Fwagent functionality, while keeping
    the Fwagent connected to flexiManage. These tasks are performed
    by the FwagentDaemon object.
    So the FwagentDaemon is responsible for:
        1. Creation and configuration the Fwagent object
        2. Running infinite loop of the Fwagent registration & WebSocket
           connection retrials, named the 'main daemon loop'.
        3. Listening for CLI commands that effect on the main daemon loop,
           like 'fwagent start', 'fwagent stop', etc.
        4. Listening for CLI commands that are designated for the Fwagent object
           itself and proxying them to it.

    The FwagentDaemon object is created by the 'fwagent daemon' command.
    """
    def __init__(self):
        """Constructor method
        """
        self.agent       = None
        self.active      = False
        self.thread_main = None

        self.SIGNALS_TO_NAMES_DICT = dict((getattr(signal, n), n) \
                                          for n in dir(signal) if n.startswith('SIG') and '_' not in n )
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT,  self._signal_handler)

    def _signal_handler(self, signum, frame):
        fwglobals.log.info("FwagentDaemon: got %s" % self.SIGNALS_TO_NAMES_DICT[signum])
        exit(1)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # The three arguments to `__exit__` describe the exception
        # caused the `with` statement execution to fail. If the `with`
        # statement finishes without an exception being raised, these
        # arguments will be `None`.
        fwglobals.log.debug("FwagentDaemon: goes to exit")
        self.stop(stop_vpp=False)  # Don't stop VPP on fwagent exit to keep it routing packets. To stop is use 'fwagent stop'
        fwglobals.log.debug("FwagentDaemon: exited")

    def _check_system(self):
        """Check system requirements.

        :returns: None.
        """
        root = os.path.dirname(os.path.realpath(__file__))
        checker = os.path.join(root, 'tools' , 'system_checker' , 'fwsystem_checker.py')
        try:
            subprocess.check_call(['python' , checker , '--check_only'])
            return True
        except subprocess.CalledProcessError as err:
            fwglobals.log.excep("+====================================================")
            fwglobals.log.excep("| System checker failed (%d)" % err.returncode)
            fwglobals.log.excep("| Fix problems and run 'fwagent start'")
            fwglobals.log.excep("| To check and configure system run 'fwsystem_checker'")
            fwglobals.log.excep("+=====================================================")
            return False

    def start(self, start_vpp=False, check_system=True):
        """Starts the main daemon loop.
        The main daemon loop keeps Fwagent connected to flexiManage.
        To stop registration/connection retrials use the 'fwagent stop' command.

        :param start_vpp:       Start router, while applying configuration to it.
        :param check_system:    Check system requirements.

        :returns: None.
        """
        fwglobals.log.debug("FwagentDaemon: start (start_vpp=%s)" % str(start_vpp))

        if self.active:
            fwglobals.log.debug("FwagentDaemon: already started, ignore")
            return

        # Reload configuration.
        fwglobals.g.load_configuration_from_file()

        # Ensure system compatibility with our soft
        if check_system and fwglobals.g.router_api.router_started:
            check_system = False    # No need to check system if VPP runs, it is too late :)
        if check_system and self._check_system() == False:
            fwglobals.log.excep("FwagentDaemon: system checker failed")

        if start_vpp:
            try:
                fwglobals.g.router_api.start_router()
                fwglobals.log.debug("FwagentDaemon: vpp started")
            except Exception as e:
                fwglobals.log.excep("FwagentDaemon: failed to start vpp: " + str(e))
                return
        self.active  = True
        self.thread_main = threading.Thread(target=self.main, name='FwagentDaemon Main Thread')
        self.thread_main.start()
        fwglobals.log.debug("FwagentDaemon: started")

    def stop(self, stop_vpp=True):
        """Stop main daemon loop.
        Once stopped, no more registration or connection retrials are performed.
        To resume registration/connection use the 'fwagent start' command.

        :param stop_vpp:        Stop router, thus cheesing the packet routing.

        :returns: None.
        """
        fwglobals.log.debug("FwagentDaemon: stop")

        # Initiate connection shutdown
        if self.active:
            self.active = False
            self.agent.disconnect()  # Break WebSocket connection event loop to get control back to main()
            fwglobals.log.debug("FwagentDaemon: disconnect from server was initiated")
        # Stop vpp ASAP, as no more requests can arrive on connection
        if stop_vpp:
            try:
                fwglobals.g.router_api.stop_router()
                fwglobals.log.debug("FwagentDaemon: vpp stopped")
            except Exception as e:
                fwglobals.log.excep("FwagentDaemon: failed to stop vpp: " + str(e))
        elif fwglobals.g.router_api.router_started:
            fwglobals.log.debug("FwagentDaemon: vpp alive, use 'fwagent stop' to stop it")
        # Stop main connection loop
        if self.thread_main:
            self.thread_main.join()
            self.thread_main = None
        fwglobals.log.debug("FwagentDaemon: stopped")

    def reset(self):
        """Restart the main daemon loop.

        :returns: None.
        """
        fwglobals.log.debug("FwagentDaemon: reset")
        self.stop()
        self.start()

    def main(self):
        """Implementation of the main daemon loop.
        The main daemon loop keeps Fwagent registered and connected to flexiManage.

        :returns: None.
        """
        fwglobals.log.info("connection loop was started, use 'fwagent stop' to stop it if needed")

        # Register with Manager
        # -------------------------------------
        prev_register_error = ''
        while self.active and not self.agent.register():
            # If registration failed due to invalid token,
            # probe the token file in loop until it is modified.
            # Otherwise sleep random period and retry registration.
            if self.agent.register_error == 'token not found' or \
               self.agent.register_error == 'invalid token':
                fwglobals.log.debug('poll %s for modification' % fwglobals.g.cfg.TOKEN_FILE)
                token   = self.agent.token
                elapsed = 0
                while token == self.agent.token and self.active:
                    time.sleep(1)               # Check self.active every second to detect Ctrl-C as soon as possible
                    elapsed += 1
                    if (elapsed % 10) == 0:     # Check if token was updated every 10 seconds
                        with open(fwglobals.g.cfg.TOKEN_FILE, 'r') as f:
                            token = f.readline()
                self.agent.token = token
            # If we got same registration reject twice - stop retrials
            elif self.agent.register_error != '' and \
                 self.agent.register_error == prev_register_error:
                fwglobals.log.info("stop registration trials, use 'fwagent start' to resume")
                self.active = False
                return
            # Sleep a little bit and retry
            else:
                prev_register_error = self.agent.register_error
                retry_sec = random.randint(fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
                fwglobals.log.info("retry registration in %d seconds" % retry_sec)
                time.sleep(retry_sec)

        # Establish main connection to Manager.
        # That start infinite receive-send loop in Fwagent::connect().
        # -------------------------------------
        while self.active:
            connected = self.agent.connect()
            if not connected:
                # If connection was closed by management because of not approved device,
                # retry the connection in few seconds.
                # Otherwise - retry connection in few minutes to prevent DDoS attack on server.
                if self.active:
                    # If immediate reconnect was requested, don't sleep
                    if self.agent.should_reconnect:
                        self.agent.should_reconnect = False
                        continue
                    # Get reconnect interval
                    if self.agent.connection_error_code in fwglobals.g.ws_reconnect_status_codes:
                        min_max = (fwglobals.g.RETRY_INTERVAL_MIN, fwglobals.g.RETRY_INTERVAL_MAX)
                    else:
                        min_max = (fwglobals.g.RETRY_INTERVAL_LONG_MIN, fwglobals.g.RETRY_INTERVAL_LONG_MAX)
                    retry_sec = random.randint(min_max[0], min_max[1])
                    # Go and sleep
                    fwglobals.log.info("retry connection in %d seconds" % retry_sec)
                    while retry_sec > 0 and self.active:
                        time.sleep(1)   # Check self.active every second to detect Ctrl-C as soon as possible
                        retry_sec -= 1

        fwglobals.log.info("connection loop was stopped, use 'fwagent start' to start it again")

def daemon():
    """Handles 'fwagent daemon' command.
    This command runs Fwagent in daemon mode. It creates the wrapping
    FwagentDaemon object that manages the instance of the Fwagent class and
    keeps it registered and connected to flexiManage.
    For more info See documentation on FwagentDaemon class.

    :returns: None.
    """
    fwglobals.log.set_target(to_syslog=True, to_terminal=False)
    fwglobals.log.info("starting in daemon mode")

    with FwagentDaemon() as agent_daemon:

        agent_daemon.agent = Fwagent(handle_sigterm=False)

        # Start the FwagentDaemon main function in separate thread as it is infinite,
        # and we need to get to Pyro4.Daemon.serveSimple() call to run rpc loop.
        agent_daemon.start()

        # Register FwagentDaemon object with Pyro framework and start Pyro request loop:
        # listen for rpc that invoke FwagentDaemon methods
        fwglobals.log.debug("FwagentDaemon is going to listen on " + fwglobals.g.FWAGENT_DAEMON_URI)
        Pyro4.Daemon.serveSimple(
            {agent_daemon: fwglobals.g.FWAGENT_DAEMON_NAME},
            host=fwglobals.g.FWAGENT_DAEMON_HOST,
            port=fwglobals.g.FWAGENT_DAEMON_PORT,
            ns=False,
            verbose=True)

def daemon_rpc(func, **kwargs):
    """Wrapper for methods of the FwagentDaemon object that runs on background
    as a daemon. It is used to fullfil CLI commands that can be designated
    either to the FwagentDaemon object itself or to the Fwagent object managed
    by the FwagentDaemon. See for example 'fwagent start' command.

    :param func:      Name of FwagentDaemon method to be called.
    :param kwargs:    Method parameters.

    :returns: None.
    """
    try:
        agent_daemon = Pyro4.Proxy(fwglobals.g.FWAGENT_DAEMON_URI)
        remote_func = getattr(agent_daemon, func)
        fwglobals.log.debug("invoke remote FwagentDaemon::%s(%s)" % (func, json.dumps(kwargs)))
        return remote_func(**kwargs)
    except Pyro4.errors.CommunicationError:
        return None
    except:
        ex_type, ex_value, ex_tb = sys.exc_info()
        Pyro4.util.excepthook(ex_type, ex_value, ex_tb)
        return None

def cli(script_fname=None, clean_request_db=True, linger=None, ignore_errors=False):
    """Handles 'fwagent cli' command.
    This command is not used in production. It assists unit testing.
    The 'fwagent cli' command injects requests into the Fwagent object,
    as it would be received from the flexiManage over network. The requests
    are read from the file, provided to the command with -f option.

    :param script_fname:        Name of file with requests to be injected.
    :param clean_request_db:    Clean request database upon inject completion.
                                Effectively this flag resets the router configuration.
    :param linger:              Sleep duration after requests were injected.
    :param ignore_errors:       Ignore errors during request execution,
                                preventing thus abnormal exit.

    :returns: None.
    """
    fwglobals.log.info("started in cli mode")
    with Fwagent() as agent:

        if script_fname:
            with open(script_fname, 'r') as f:
                requests = json.loads(f.read())
                for req in requests:
                    if 'commands' in req:
                        for c in req['commands']:
                            eval(c)
                    else:
                        reply = agent.handle_received_request(req)
                        if reply['ok'] == 0 and ignore_errors == False:
                            break
            if linger:  # give tester a time to kill vpp and to test watchdog
                time.sleep(linger)
            if clean_request_db:
                fwglobals.g.router_api.db_requests.clean()
            return

        # If no script file was provided, read requests from stdin
        while(True):
            request = raw_input(__file__ +"> ")
            if request == '?' or request == 'h' or request == 'help':
                print('enter "quit", "load <file with requests>" or "<request>" in JSON format')
            elif request == 'q' or request == 'quit' or request == 'exit':
                return
            else:
                req = json.loads(request)
                agent.handle_received_request(req)


if __name__ == '__main__':
    import argcomplete
    import argparse

    fwglobals.initialize()
    loadsimulator.initialize()

    command_funcs = {
                    'version':lambda args: version(),
                    'register':lambda args: register(),
                    'connect': lambda args: connect(),
                    'reset': lambda args: reset(soft=args.soft),
                    'stop': lambda args: stop(reset_router_config=args.reset_softly, stop_router=True if args.dont_stop_vpp is False else False),
                    'start': lambda args: start(start_router=args.start_router),
                    'daemon': lambda args: daemon(),
                    'simulate': lambda args: loadsimulator.g.simulate(count=args.count),
                    'show': lambda args: show(
                        agent_info=args.agent,
                        router_info=args.router),
                    'cli': lambda args: cli(
                        script_fname=args.script_fname,
                        clean_request_db=args.clean,
                        linger=float(args.linger),
                        ignore_errors=args.ignore_errors)}

    parser = argparse.ArgumentParser(
        description="Device Agent for FlexiWan orchestrator\n" + \
                    "--------------------------------------------------------------\n" + \
                    "Use 'fwagent.py <command> --help' for help on specific command",
        formatter_class=argparse.RawTextHelpFormatter)
    subparsers = parser.add_subparsers(help='Agent commands', dest='command')
    subparsers.required = True
    parser_version = subparsers.add_parser('version', help='show components and their versions')
    parser_register = subparsers.add_parser('register', help='register device to FlexiWan orchestrator')
    parser_connect = subparsers.add_parser('connect', help='connect device to FlexiWan orchestrator')
    parser_reset = subparsers.add_parser('reset', help='Reset device: clear router configuration and remove device registration')
    parser_reset.add_argument('-s', '--soft', action='store_true',
                        help="clean router configuration only, device remains registered")
    parser_stop = subparsers.add_parser('stop', help='Stop router and reset interfaces')
    parser_stop.add_argument('-s', '--reset_softly', action='store_true',
                        help="reset router softly: clean router configuration")
    parser_stop.add_argument('-r', '--dont_stop_vpp', action='store_true',
                        help="stop agent connection loop only")
    parser_start = subparsers.add_parser('start', help='Resumes daemon connection loop if it was stopped by "fwagent stop"')
    parser_start.add_argument('-r', '--start_router', action='store_true',
                        help="start router before loop is started")
    parser_daemon = subparsers.add_parser('daemon', help='Run agent in daemon mode: infinite register-connect loop')
    parser_simulate = subparsers.add_parser('simulate', help='register and connect many fake devices to FlexiWan orchestrator')
    parser_simulate.add_argument('-c', '--count', dest='count',
                              help="How many devices to simulate")
    parser_show = subparsers.add_parser('show', help='Prints various information to stdout')
    parser_show.add_argument('--router', choices=['configuration' , 'state' , 'request_db'],
                        help="show various router parameters")
    parser_show.add_argument('--agent', choices=['version'],
                        help="show various agent parameters")
    parser_cli = subparsers.add_parser('cli', help='runs agent in CLI mode: read orchestrator requests from command line')
    parser_cli.add_argument('-f', '--script_file', dest='script_fname',
                        help="File with requests to be executed")
    parser_cli.add_argument('-c', '--clean', action='store_true',
                        help="clean request database on exit")
    parser_cli.add_argument('-l', '--linger', dest='linger', default=0,
                        help="number of seconds to wait after completion (is needed for watchdog tests)")
    parser_cli.add_argument('-i', '--ignore_errors', action='store_true',
                        help="don't stop execution if some of requests failed")
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    fwglobals.log.debug("---> exec " + str(args), to_terminal=False)
    command_funcs[args.command](args)
