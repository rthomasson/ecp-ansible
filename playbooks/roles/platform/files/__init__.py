# Copyright (c) 2018, BlueData Software, Inc.

import subprocess
import os
import ast
import json
import socket
from tabulate import tabulate
import xml.etree.ElementTree as ET
import datetime
import time
from ..util import executeCommand

from bluedata.config import BDSConfigParser, BDSharedConfigParser
from bluedata.config import BDS_HA_ENABLED, BDS_HA_ENABLED_YES, \
                            BDS_GLOBAL_OSMAJOR, BDS_GLOBAL_INSTALL_DIR, \
                            BDS_GLOBAL_OSFAMILY, BDS_NETWORK_HOSTNAME
import bluedata.mgmt as mgmt
import re

# HA specific shared defines accessed by bdconfig. Exported.
HA_NORMAL = 'hainfo'
HA_JSON = 'ha_json'

# Private non-exported globals.

# Strings and indexes into local BDSConfig database values returned by _fetchHAConfig

_primary_role_string = 'primary'
_shadow_role_string = 'shadow'
_arbiter_role_string = 'arbiter'
_orig_primary_index = 0
_orig_shadow_index = 1
_orig_arbiter_index = 2
_bdm_workers_str = "bdm_workers"
_bds_network_primaryip_str = 'bds_network_primaryip'
_bds_ha_nodes_str = 'bds_ha_nodes'

#mnesia indexes into _get_mnesia_node_states output

_nodes_index_string = "Nodes"
_cluster_index_string = "Cluster"
_resources_string = 'resources'
_failures_string = 'failures'

#indexes into pcs-related dictionary elements and reference fields

_pcs_resource_string = "pcs_resource_status"
_pcs_resource_info_str = "pcs_resource_info"
_active_str = "active"
_orphaned_str = "orphaned"
_managed_str = "managed"
_id_str = "id"
_pcs_failures_list_str = "pcs_failures_list"
_pacemaker_service_name_str = 'bds_pl_svc'

# Looking for "Stopped", "Starting", "Started", etc. in pcs_resource_status.
pcs_resource_status_index = 2

# Various dictionary elements referenced within the output of GatherHAConfigDict.

_ha_enabled_str = "ha_enabled"
_timestamp_str = "timestamp"
_local_system_str = "local_system"
_local_role_str = "local_role"
_mnesia_node_states_str = "mnesia_node_states"
_mnesia_node_roles_str = "mnesia_node_roles"
_pcs_node_active_stat_str = "pcs_node_active_status"
_config_changed_from_orig_str = "config_changed_from_orig"
_original_config_str = "original_config"

# These are mnesia cluster states we really care about and will likely display.
_init_cluster_state = "Init"
_good_cluster_state = "Normal"
_degraded_cluster_state = "Degraded"

# Taken from everest/mgmt/controller/pl_ha ClusterState enum, but munged a bit to
# xlate the string number to a string interpreted text value.
_num_xlate_cluster_state_dict = {"100" : "First Cluster State",
                                 "101" : _init_cluster_state,
                                 "102" : _good_cluster_state,
                                 "103" : _degraded_cluster_state,
                                 "104" : "Unknown Cluster State",
                                 "105" : "Last Cluster State",
                                 "200" : "First Controller State",
                                 "201" : "Shadow",
                                 "202" : "Controller",
                                 "203" : "Arbiter",
                                 "204" : "Last Node Type",
                                 "300" : "First Controller Event",
                                 "301" : "Failover",
                                 "302" : "Failback",
                                 "303" : "Recoverable Error",
                                 "304" : "Error Controller Event",
                                 "305" : "Last Controller Event",
                                 "400" : "First PaceMaker State",
                                 "401" : "Active",
                                 "402" : "Standby",
                                 "403" : "Offline",
                                 "404" : "Error PaceMaker State",
                                 "405" : "Last PaceMaker State"}


def _ha_get_bdsconfig_keys():
    '''
        Get all the BDS keys and toss them back as a dictionary. This is identical to the
        one in bdconfig.  TODO:  Factor it out to a generic routine.
    '''

    d1 = BDSConfigParser().getAllSafe()
    d2 = BDSharedConfigParser().getAllSafe()
    return dict(d1.items() + d2.items())

# Global all keys.
all_keys = _ha_get_bdsconfig_keys()

def _fetchHAConfig():
    '''
        Fetch HA-specific current configuration info.  This may be used just to print,
        or when eventually enabled, to assess HA config's suitability for local failover
        request.
    '''

    # Static Indices into returned mgmt.fetchMgmtInfo bdm_workers data
    role_field_index = 5
    ip_field_index = 2
    ha_node_roles_set = set([_primary_role_string,
                         _shadow_role_string,
                         _arbiter_role_string])

    decodedOut = mgmt.fetchMgmtInfo(_bdm_workers_str, all_keys)

    # Build dictionary with role as key, IP addr as value, e.g. {"primary" : "10.1.32.76"}
    ip_given_role_dict = dict((node[role_field_index],node[ip_field_index])
                         for node in decodedOut if node[role_field_index] in ha_node_roles_set)

    # Get identifier for this specific node that invoked bdconfig.
    local_node_ip = all_keys[_bds_network_primaryip_str]

    # This list will reflect the ORIGINAL configuration in a list, in the order
    # [primary, shadow, arbiter].  The CURRENT config may not be in this order,
    # so by comparing them we can determine whether HA is in original config or
    # has reversed its config by some odd number of failovers.
    ha_nodes_list = all_keys[_bds_ha_nodes_str].split(",")

    return ip_given_role_dict, local_node_ip, ha_nodes_list


def _printHAConfig(ip_given_role_dict,
                   local_node_ip,
                   ha_nodes_list,
                   opt_config_dict = None):
    '''
        Print current HA configuration, and, if changed from original configuration,
        also print the original config.  Static information is guaranteed, but the
        output from status calls may or may not be.
    '''

    # We can only print HA status info from an HA node since that is where the mnesia
    # and Pacemaker information are located.

    if local_node_ip not in ha_nodes_list:
        print "Please run this command from current primary node:  " + ip_given_role_dict[_primary_role_string]
        return

    # When output is not applicable, like on an arbiter node, we can
    # display this string in the output.
    _not_applicable = "N/A"

    if opt_config_dict is None:
        all_config_dict = gatherHAConfigDict(ip_given_role_dict, local_node_ip, ha_nodes_list)
    else:
        all_config_dict = opt_config_dict

    role_given_ip_dict = dict((v, k) for k,v in ip_given_role_dict.items())

    if role_given_ip_dict[local_node_ip] != _arbiter_role_string:
        local_table_elems = [[role_given_ip_dict[local_node_ip],
                              local_node_ip,
                              all_config_dict[_mnesia_node_states_str][_nodes_index_string][local_node_ip],
                              all_config_dict[_pcs_node_active_stat_str][local_node_ip]]]

    else:
        local_table_elems = [[role_given_ip_dict[local_node_ip],
                              local_node_ip,
                              all_config_dict[_mnesia_node_states_str][_nodes_index_string][local_node_ip],
                              _not_applicable]]

    print "HA is Enabled.\n\nTimestamp:\t" + all_config_dict['timestamp'] + "\n"

    if "pcs_resource_status" in all_config_dict:
        pcs_resource_elems = [[all_config_dict[_pcs_resource_string][0],
                               all_config_dict[_pcs_resource_string][1],
                               all_config_dict[_pcs_resource_string][2]]]
        print tabulate(pcs_resource_elems, headers=['Cluster Monitoring Svc', 'ID', 'Service State'])
        print ''

    if all_config_dict[_mnesia_node_states_str][_cluster_index_string][0]:
        # Gather info from the single cluster entry, which is a list of items.
        cluster_table_elems = [[all_config_dict[_mnesia_node_states_str][_cluster_index_string][0],
                               all_config_dict[_mnesia_node_states_str][_cluster_index_string][1]]]

        print tabulate(cluster_table_elems, headers=['Cluster IP',
                                                     'Mnesia State'])
        print ''

    print tabulate(local_table_elems, headers=['Local Role     ',
                                               'IP',
                                               'Mnesia Node State',
                                               'PCS Status Active'])
    print ''

    if role_given_ip_dict[local_node_ip] != _arbiter_role_string:
        all_node_elems = [[_primary_role_string,
                            ip_given_role_dict[_primary_role_string],
                            all_config_dict[_mnesia_node_states_str][_nodes_index_string][ip_given_role_dict[_primary_role_string]],
                            all_config_dict[_pcs_node_active_stat_str][ip_given_role_dict[_primary_role_string]]
                          ],
                          [_shadow_role_string,
                            ip_given_role_dict[_shadow_role_string],
                            all_config_dict[_mnesia_node_states_str][_nodes_index_string][ip_given_role_dict[_shadow_role_string]],
                            all_config_dict[_pcs_node_active_stat_str][ip_given_role_dict[_shadow_role_string]]
                          ],
                          [_arbiter_role_string,
                            ip_given_role_dict[_arbiter_role_string],
                            all_config_dict[_mnesia_node_states_str][_nodes_index_string][ip_given_role_dict[_arbiter_role_string]],
                            _not_applicable
                          ],
                         ]
    else:
        all_node_elems = [[_primary_role_string,
                            ip_given_role_dict[_primary_role_string],
                            all_config_dict[_mnesia_node_states_str][_nodes_index_string][ip_given_role_dict[_primary_role_string]],
                            "Unavailable to arbiter node"
                          ],
                          [_shadow_role_string,
                            ip_given_role_dict[_shadow_role_string],
                            all_config_dict[_mnesia_node_states_str][_nodes_index_string][ip_given_role_dict[_shadow_role_string]],
                            "Unavailable to arbiter node"
                          ],
                          [_arbiter_role_string,
                            ip_given_role_dict[_arbiter_role_string],
                            all_config_dict[_mnesia_node_states_str][_nodes_index_string][ip_given_role_dict[_arbiter_role_string]],
                            _not_applicable

                          ],
                         ]

    print tabulate(all_node_elems, headers=['Role ',
                                            'IP',
                                            'Node State',
                                            'PCS Status Active'])


    if _pcs_failures_list_str in all_config_dict:
        # We have a list of dictionaries describing failures.
        failures_list = all_config_dict[_pcs_failures_list_str]
        if len(failures_list) > 0:
            print "\npcs failures:\n"
            for entry in failures_list:
                print str(entry)

    if all_config_dict[_config_changed_from_orig_str]:
        print "\nConfiguration has changed from original:\n"
        print tabulate(all_config_dict[_original_config_str], headers=['Original Config', 'IP'])
        print ''
    else:
        print "\nOriginal configuration is currently active.\n"


def _printHAConfigJson(ip_given_role_dict, local_node_ip, ha_nodes_list):
    '''
        Gather all the information and stuff it into a dictionary suitable for
        emitting as a json.
    '''
    if local_node_ip not in ha_nodes_list:
        timestamp = str(datetime.datetime.now())
        output_dict = {"ERROR" : "Non-HA role system: Please run from primary node: " + ip_given_role_dict[_primary_role_string],
                       _timestamp_str  : timestamp}
    else:
        output_dict = gatherHAConfigDict(ip_given_role_dict,
                                         local_node_ip,
                                         ha_nodes_list)

    print json.dumps(output_dict)


def gatherHAConfigDict(input_ip_given_role_dict = None,
                       input_local_node_ip = None,
                       input_ha_nodes_list = None):
    '''
        This routine gathers information from:  Mnesia, PCS, and BDSConfig (passed in),
        refactoring it into a single dictionary for ease of reference and printing.

        Since it can be called from external, the caller may not have the above internal
        libs, so we will fetch them if they're not defined.  This way a caller can get
        everything in one place in one call.
    '''

    if input_ip_given_role_dict is None or \
       input_local_node_ip is None or \
       input_ha_nodes_list is None:
        ip_given_role_dict, local_node_ip, ha_nodes_list = _fetchHAConfig()
    else:
        ip_given_role_dict = input_ip_given_role_dict
        local_node_ip = input_local_node_ip
        ha_nodes_list = input_ha_nodes_list

    pcs_node_status_dict = None
    service_status_dict = None
    role_given_ip_dict = dict((v, k) for k,v in ip_given_role_dict.items())

    # Output is a dict with two keys - "Nodes" and "Cluster" - each pointing to
    # a dict describing them.
    mnesia_node_states = _get_mnesia_node_states()

    output_dict = {_ha_enabled_str          : True,
                   _local_system_str        : local_node_ip,
                   _local_role_str          : role_given_ip_dict[local_node_ip],
                   _mnesia_node_states_str  : mnesia_node_states,
                   _mnesia_node_roles_str   : ip_given_role_dict,
                   _timestamp_str           : str(datetime.datetime.now())}

    if role_given_ip_dict[local_node_ip] != _arbiter_role_string:
        # pcs service does not run on the arbiter node.

        pcs_node_status_dict, service_status_dict, failures_list, pcs_resource_list = _get_pcs_status()

        output_dict[_pcs_node_active_stat_str] = pcs_node_status_dict

        if service_status_dict is not None:
            output_dict[_pcs_resource_info_str] = service_status_dict

        if failures_list is not None:
            output_dict[_pcs_failures_list_str] = failures_list

        output_dict[_pcs_resource_string] = pcs_resource_list

    # Config is not original.  Add the original config to json.
    if role_given_ip_dict[ha_nodes_list[_orig_primary_index]] != _primary_role_string:
        output_dict[_config_changed_from_orig_str] = True
        output_dict[_original_config_str] = \
                         [[_primary_role_string, ha_nodes_list[_orig_primary_index]],
                          [_shadow_role_string,  ha_nodes_list[_orig_shadow_index]],
                          [_arbiter_role_string, ha_nodes_list[_orig_arbiter_index]]
                   ]
    else:
        output_dict[_config_changed_from_orig_str] = False

    return output_dict


def _get_mnesia_node_states():
    '''
        Get the HA state of the cluster nodes and return a dict of IP to State.
    '''

    # This command gets us raw data about the state of the cluster, which we must parse.
    # We only want the data line, not any of the others.

    anode_string = "anode"
    cnode1_string = "cnode1"
    cnode2_string = "cnode2"
    clstate_string = "clstate"

    command = "/opt/bluedata/common-install/bd_mgmt/bin/bd_mgmt ha read_record bd_ha_record | grep {"
    raw_hastate, exitCode = _do_command(command, False)

    # It doesn't come out very clean so it has to be eval'd literally or it won't
    # make it through the dict conversion parse.
    hastate_dict = ast.literal_eval(raw_hastate.strip())

    # Raw Data Input Example:
    #           {'version': '1.0', 'anode': '10.32.1.7|203|UP',
    #            'cnode2': '10.32.1.175|201|UP',
    #            'cnode1': '10.32.1.76|202|UP',
    #            'clstate': '10.32.1.96|102|10.32.1.76'}

    cnode1_state =  hastate_dict[cnode1_string].split('|')
    cnode2_state =  hastate_dict[cnode2_string].split('|')
    anode_state  =  hastate_dict[anode_string ].split('|')
    cl_state = hastate_dict[clstate_string ].split('|')

    # Looking at the array at the top, the node states and statuses are a
    # bit conflated, so we need to normalize for that.  We want the node
    # states for cnode1, cnode2, and anode, but we want the node state for
    # clstate, because that's not really a node - it's a cluster description
    # with cluster status in the place where node_type would be for cnode[x]
    # and anode.
    node_type_index = 1
    node_state_index = 2
    cluster_state_index = 1
    IP_index = 0

    cluster_IP = cl_state[IP_index]

    # Example entry:{"Cluster": ("10.32.1.96": "Normal"),
    #                "Nodes":   {"10.32.1.76": "UP",
    #                            "10.32.1.7": "UP",
    #                            "10.32.1.175": "UP"}}

    return {_nodes_index_string : {cnode1_state[IP_index]: cnode1_state[node_state_index],
                                   cnode2_state[IP_index]: cnode2_state[node_state_index],
                                   anode_state[IP_index]: anode_state[node_state_index]},
            _cluster_index_string : [cluster_IP,_num_xlate_cluster_state_dict[cl_state[cluster_state_index]]]
           }


def _get_pcs_resource_state():
    '''
        Get the pcs resource state of the bds_pl_svc.  If it's not running than we
        need to know this.
    '''
    # This command gets us raw data about the state of the cluster, which we must parse
    # a little.
    osfamily = all_keys.get(BDS_GLOBAL_OSFAMILY)
    if osfamily == 'centos':
        command = "/usr/sbin/pcs resource"
    elif osfamily == 'suse':
        command = "/usr/sbin/crm resource status"
    else:
        return None

    raw_pcs_state, outputStatus = _do_command(command, True)
    return raw_pcs_state.split()


def _get_pcs_resource_state_value():
    '''
        Small helper function to extract the pacemaker (pcs) daemon state value
        e.g. 'Started'.
    '''

    pcs_resource_list = _get_pcs_resource_state()
    if pcs_resource_list:
        return pcs_resource_list[pcs_resource_status_index]

    return ''



def _do_command(command, asSudo = False):
    '''
        Execute command using executeCommand
    '''

    exitCode, output, errString = executeCommand(command, RunAsSudo=asSudo)

    if exitCode == 0:
        return output, exitCode
    else:
        print "Attempt to execute command: [" + command + "] Failed. Error: exitCode is " + str(exitCode)
        print "error string: [" + errString + "]"
        return None, exitCode


def _get_pcs_info_raw_xml():
    '''
        Get the pcs HA state of the cluster nodes and return it in XML.  The XML needs
        to be processed further.  It is GNARLY.

        This command gets us xml output about the state of the cluster, which we must parse.
        Turns out that this is the exact command that 'pcs status' runs - I checked the pcs
        source code.
    '''
    output, exitCode  = _do_command('/usr/sbin/crm_mon --as-xml', True)
    return output.replace('\r', '').replace('\n', ''), exitCode


def _get_pcs_status() :
    '''
        Get the XML output from pcs status and translate it into usable python dicts.
        If the call fails, the returned dicts will be 'None'.
    '''
    raw_xml_dict = {}
    status_dict = {}
    resources_dict = {}
    failures_list = []

    # index strings into raw xml conversion dictionaries
    xml_node_str = 'nodes'
    xml_node_children_str = '_children'
    xml_attrib_str = 'attrib'
    xml_name_str = 'name'
    xml_online_str = 'online'

    # Substitute our preferred style for string representations for a limited set of values.
    map_status_dict = {'true':True, 'false':False, '1':1, '2':2, '3':3}

    xml_out, outstatus = _get_pcs_info_raw_xml()
    pcs_resource_list = _get_pcs_resource_state()

    if outstatus is not 0:
        return None, None

    root = ET.fromstring(xml_out)

    # Build the base normalized dictionary we will use to extract further.
    # Warning:  The raw xml is GNARLY. This makes it a bit more manageable
    # by giving us a better way to access the elements.
    root_childcount =  len(root._children)
    for x in range(0, root_childcount) :
         raw_xml_dict[root._children[x].tag] = root._children[x].__dict__

    # Extract the IP address and Status from the pcs status and convert to a dict. Remap a few values
    # to make them easier to consume at a higher level.
    # e.g. {'10.32.1.76': 'true', '10.32.1.175': 'true'} becomes
    #    {'10.32.1.76': True, '10.32.1.175': True}

    childcount = len(raw_xml_dict[xml_node_str][xml_node_children_str])
    for y in range(childcount):
        status_dict[socket.gethostbyname(raw_xml_dict[xml_node_str][xml_node_children_str][y].__dict__[xml_attrib_str][xml_name_str])] =  \
            raw_xml_dict[xml_node_str][xml_node_children_str][y].__dict__[xml_attrib_str][xml_online_str]
        for key, value in status_dict.iteritems():
            if value in map_status_dict.keys():
                status_dict[key] = map_status_dict[value]

    # We have statuses.  Now get the bds_pl_svc dict information. We don't know how many there are so we
    # filter for it.  Right now I only see a single service but I don't know what others may lurk in our
    # customer environments so I'm not making any assumptions about how many may be present.
    #
    # I will remap the input text values to more useful values using the map_status_dict entries.
    #
    # e.g. {'managed': 'true', 'nodes_running_on': '1', 'id': 'bds_pl_svc', 'resource_agent': 'ocf::bluedata:BdRa',
    #       'failed': 'false', 'role': 'Started', 'failure_ignored': 'false', 'active': 'true', 'orphaned': 'false',
    #       'blocked': 'false'}
    #
    # becomes:
    #
    #    {'managed': True, 'nodes_running_on': 1, 'id': 'bds_pl_svc', 'resource_agent': 'ocf::bluedata:BdRa',
    #     'failed': False, 'role': 'Started', 'failure_ignored': False, 'active': True, 'orphaned': False,
    #     'blocked': False}
    #
    # It's subtle but extremely useful.
    #
    service_count = len(raw_xml_dict[_resources_string][xml_node_children_str])
    if service_count > 0:
        for z in range(service_count):
            if raw_xml_dict[_resources_string][xml_node_children_str][z].__dict__[xml_attrib_str][_id_str] == _pacemaker_service_name_str :
                resources_dict = raw_xml_dict[_resources_string][xml_node_children_str][z].__dict__[xml_attrib_str]
                for key, value in resources_dict.iteritems():
                    # Normalize for boolean True and False instead of 'true' and 'false', 1 vs. "1"
                    if value in map_status_dict.keys():
                        resources_dict[key] = map_status_dict[value]
                break;
    else:
        # Gather the error info and put it in an error table.
        fail_count = len(raw_xml_dict[_failures_string][xml_node_children_str])
        if fail_count > 0:
            for w in range (fail_count):
                failures_list.append( raw_xml_dict[_failures_string][xml_node_children_str][w].__dict__[xml_attrib_str])
        else:
            resources_dict = None

    return status_dict, resources_dict, failures_list, pcs_resource_list


def _parse_erlang_output(string):
    '''
        Extract erlang error code from output.
    '''

    REGEX = "{exit,(\d+),(.+)}"
    search = re.search(REGEX, string, re.DOTALL)
    if search is not None:
        exit_code, output  =  search.groups()
        return (output, int(exit_code))
    else:
        return ("", 0)


def _ha_remote_command(local_ip, remote_node_ip, command, is_sudo_at_remote=False):
    '''
        Execute command on another node of the HA cluster.
    '''

    remote_rpc_function = "sudo_cmd" if is_sudo_at_remote else "cmd"
    erlang_node = "'bd_mgmt@" + remote_node_ip + "'"

    TIMEOUT_5_MIN_MS = str(5 * 60 * 1000)
    rpc_cmd = mgmt.construct_rpc_command(all_keys[BDS_GLOBAL_INSTALL_DIR],
                                         local_ip, "bd_os_client_rpc", remote_rpc_function,
                                         [erlang_node, command, "BDConfig-HAFailover",
                                         TIMEOUT_5_MIN_MS], [True, False, False, True])

    erlang_output, err_code = _do_command(rpc_cmd, asSudo = False)
    if err_code == 0 :
        output, exit_code = _parse_erlang_output(erlang_output)
        if exit_code == 0 :
            return output
        else:
            return "Call failed with exit_code " + str(exit_code) + "output: " + output
    else:
        print "Remote Command to " + remote_node_ip + " failed."
        print "Remote Command: [" + rpc_cmd + "] failed with exit code " + str(err_code)
        return "FAILED"


def processHAFailover():
    '''
        Initiate a failover.  This can only be invoked from the Primary node, and if all
        the health conditions are met.
    '''

    global all_keys
    good_state = "UP"
    good_cluster_state = "Normal"
    good_pcs_resource_status = "Started"
    recheck_counter = 60

    # Failover is not enabled for RHEL 6.x.
    if all_keys[BDS_GLOBAL_OSFAMILY] == 'suse':
        print "HA Failover is not supported on SLES."
        return

    # See if HA is even enabled yet.
    if BDS_HA_ENABLED not in all_keys or \
       all_keys[BDS_HA_ENABLED] != BDS_HA_ENABLED_YES:
        print "HA is not enabled."
        return

    # HA and Failover are both enabled and supported.  Collect status information.
    ip_given_role_dict, local_node_ip, ha_nodes_list = _fetchHAConfig()
    if local_node_ip not in ha_nodes_list:
        print "Please run this command from current primary node:  " + ip_given_role_dict[_primary_role_string] + " ."
        return

    config_dict = gatherHAConfigDict(ip_given_role_dict, local_node_ip, ha_nodes_list)
    role_given_ip_dict = dict((v, k) for k,v in ip_given_role_dict.items())

     # Only do anything if we are on the primary node.
    if role_given_ip_dict[local_node_ip] != _primary_role_string:
        print "Can't initiate failover from this node, which is role: " + role_given_ip_dict[local_node_ip]
        print "Run this command from current primary node:  " + ip_given_role_dict[_primary_role_string] + " ."
        print ''
        _printHAConfig(ip_given_role_dict,
                       local_node_ip,
                       ha_nodes_list,
                       config_dict)
        return

    # Do bd_mgmt ping to all nodes to ensure they're all actually responding to bd_mgmt control.
    for remoteip in ha_nodes_list:
        ping_command ='/opt/bluedata/common-install/bd_mgmt/bin/bd_mgmt ping '
        ping_out = _ha_remote_command(local_node_ip, remoteip, ping_command, is_sudo_at_remote=False)
        # Return val is actually [\"pong\"\n] with the quotes and newline, so just slice them out.
        if "pong" not in ping_out:
            print "ERROR:  Unable to do bd_mgmt ping of node: " + role_given_ip_dict[remoteip] + ' at ip ' + remoteip + '.'
            return

    # Check to see if pcs resource status is OK.
    pcs_resource_status = config_dict[_pcs_resource_string][pcs_resource_status_index]
    if pcs_resource_status != good_pcs_resource_status:
        print "Pacemaker service is unhealthy. pcs resource status is: " + pcs_resource_status + " .\n"
        print "Unable to initiate failover."
        _printHAConfig(ip_given_role_dict,
                       local_node_ip,
                       ha_nodes_list,
                       config_dict)
        return

    # Check that all mnesia node states are Up
    for k, v in config_dict[_mnesia_node_states_str][_nodes_index_string].items():
        if v != good_state :
            print "\nNode: " + k + "in EPIC DB is unhealthy: " + v + \
                  " . Unable to initiate failover.\n"
            _printHAConfig(ip_given_role_dict,
                           local_node_ip,
                           ha_nodes_list,
                           config_dict)
            return

    # Check that the Cluster state is Normal.
    cluster_state = config_dict[_mnesia_node_states_str][_cluster_index_string][1]
    if cluster_state != good_cluster_state:
        print "\nCluster State is unhealthy: " + cluster_state + \
              " . Unable to initiate failover.\n"
        _printHAConfig(ip_given_role_dict,
                       local_node_ip,
                       ha_nodes_list,
                       config_dict)
        return

    # Check that the pcs node active status is True
    for p_k, p_v in config_dict[_pcs_node_active_stat_str].items():
        if p_v is False :
            print "\pcs node status for: " + p_k + " is unhealthy: " + p_v + \
                  " . Unable to initiate failover.\n"
            _printHAConfig(ip_given_role_dict,
                           local_node_ip,
                           ha_nodes_list,
                           config_dict)
            return

    # Check that the pcs resource service bds_pl_svc is up and healthy
    if _pcs_resource_info_str in config_dict.keys():
        if _active_str in config_dict[_pcs_resource_info_str] and \
           _orphaned_str in config_dict[_pcs_resource_info_str] and \
           _managed_str in config_dict[_pcs_resource_info_str] :

            pcs_active = config_dict[_pcs_resource_info_str][_active_str]
            pcs_orphaned = config_dict[_pcs_resource_info_str][_orphaned_str]
            pcs_managed = config_dict[_pcs_resource_info_str][_managed_str]
            pcs_id = config_dict[_pcs_resource_info_str][_id_str]

            if pcs_active is False or pcs_orphaned is True or pcs_managed is False :
                print "\nPCS State for service: " + pcs_id + " is unhealthy.  Unable to initiate failover."
                _printHAConfig(ip_given_role_dict,
                               local_node_ip,
                               ha_nodes_list,
                               config_dict)
                return
        else:
            print "\nNo PCS resource info to check status!  PCS is unhealthy.  Unable to initiate failover."
            _printHAConfig(ip_given_role_dict,
                            local_node_ip,
                            ha_nodes_list,
                            config_dict)
            return
    else:
        print "\nNo PCS resource info to check status!  PCS is unhealthy.  Unable to initiate failover."
        _printHAConfig(ip_given_role_dict,
                        local_node_ip,
                        ha_nodes_list,
                        config_dict)
        return

    # Cluster Nodes in Mnesia are OK, cluster state in mnesia is OK, pcs service is OK.
    # Let's do this!

    local_node_name = all_keys[BDS_NETWORK_HOSTNAME]

    # Shadow will become primary, so we want to send this command to the 'new'
    # primary.  We know what that address will be so let's just stash it here
    # rather than pulling all the info all over again.

    old_shadow_node_ip = ip_given_role_dict[_shadow_role_string]

    print "EPIC HA Failover initiated at: " + str(datetime.datetime.now())

    command1 = '/usr/sbin/pcs cluster standby '+ local_node_name
    _do_command(command1, asSudo = True)

    pcs_value = _get_pcs_resource_state_value()
    while pcs_value != good_pcs_resource_status and recheck_counter > 0:
        time.sleep(10)
        print "Waiting for pacemaker 'Started' state; state is " + pcs_value + "..."
        recheck_counter -= 1
        pcs_value = _get_pcs_resource_state_value()

    print "Finished waiting for state change. State is " + pcs_value + "."
    # either pcs is started or we have bigger problems.  Only call start
    # after pcs resource value is at 'Started'.
    if pcs_value == 'Started' :

        print  "Bringing up cluster..."
        command2 = '/usr/sbin/pcs cluster unstandby '+ local_node_name
        _do_command(command2, asSudo = True)

        print "Cleaning up cluster state..."

        # The new primary which is not us has to invoke ha_engine_cli.py nodeup using
        # our local IP as the arg. We can't call this on ourselves locally as we are
        # no longer the primary at this stage.

        command3 = '/usr/lib/python2.7/site-packages/bds_ha/ha_engine_cli.py nodeup ' + local_node_ip
        _ha_remote_command(local_node_ip, old_shadow_node_ip, command3, is_sudo_at_remote=False)

        # Give everything a little time to settle down.
        time.sleep(5)
    else:
        # PCS never came back.  We have a bigger problem.  We could try
        # restarting pcs, but at this point the failover may not have
        # actually occurred so we don't really know which node is the
        # one we would be issuing the remote command to.
        print "ERROR: Pacemaker has not restarted.  Unable to complete HA Failover task."
        return

    print "\nEPIC HA Failover complete at: " + str(datetime.datetime.now())
    print "\nPlease check cluster status below for more information.\n"

    all_keys = _ha_get_bdsconfig_keys()

    ip_given_role_dict2, local_node_ip2, ha_nodes_list2 = _fetchHAConfig()
    _printHAConfig(ip_given_role_dict2, local_node_ip2, ha_nodes_list2)
    return


def processHAGetInfo(hainfo_option):
    '''
        Get HA related information, emitted either in readable human text or in json.
    '''
    # HA is enabled. BDS_HA_ENABLED will not exist in keys on a new install so we
    # need to check for that before dereferencing it in the dict.
    if BDS_HA_ENABLED in all_keys and all_keys[BDS_HA_ENABLED] == BDS_HA_ENABLED_YES:
        ip_given_role_dict, local_node_ip, ha_nodes_list = _fetchHAConfig()

        if hainfo_option == HA_NORMAL:
            _printHAConfig(ip_given_role_dict, local_node_ip, ha_nodes_list)
        else:
            _printHAConfigJson(ip_given_role_dict, local_node_ip, ha_nodes_list)

    # HA is not enabled.
    else:
        timestamp = str(datetime.datetime.now())

        if hainfo_option == HA_NORMAL:
            print "\n" + timestamp +"\t HA is NOT Enabled.\n"
        elif hainfo_option == HA_JSON:
            output_dict = {_ha_enabled_str : False,
                           _timestamp_str  : timestamp}
            print json.dumps(output_dict)
        else:
            print "Invalid ha arg!"
