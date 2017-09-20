"""
Check if user is admin.
For local user, check if s/he is in local administrator
For domain user, it is possible to be in both local &/or domain administrator group
but we return the higher of the two types 
"""
from EmpireAPIWrapper import empireAPI
from empire_settings import EMPIRE_SERVER, EMPIRE_PWD, EMPIRE_USER
from empire_autocomplete import situational_awareness

def run(API, agent_name):
    """
    Returns admin type, otherwise None
    \n:param API: EmpireAPIWrapper object
    \n:param agent_name: name of agent
    \n:return type: str or None
    """
    agent = API.agent_info(agent_name)['agents']
    if len(agent) == 0: # checks for no agents at all or no such agent
        raise ValueError('No agent')
    agent_details = agent[0]
    # either local/domain user, still check if user is in local administrators
    opts = {'Agent': agent_name, 'command': 'net localgroup Administrators'}
    localadmin_query_result = API.agent_run_shell_cmd_with_result(agent_name, opts)
    if localadmin_query_result is None:
        raise ValueError('fail to run "net localgroup Administrator", check empire console')

    # first case: for a local user, check if s/he is local admin group
    if agent_details['hostname'] in agent_details['username']:
        target_username = agent_details['username'].replace(agent_details['hostname']+'\\', "")
        if target_username in localadmin_query_result:
            return "Local"
    else: # 2nd case, for a domain user, we check if its in Domain/Local Admin group
        target_username = agent_details['username'].split('\\')[1]
        # options for the module, required options are prefixed (required_*)
        opts = situational_awareness.network_powerview_get_group.options
        if 'Admin' in API.module_exec_with_result(situational_awareness.network_powerview_get_group.path, \
        {opts.required_agent: agent_name, opts.username: target_username}, agent_name):
            return 'Domain' # there are other types of admin eg. Enterprise, Schema Admin..
        # 3rd case, a domain user could be added to local admin group
        if agent_details['username'] in localadmin_query_result:
            return 'Local'
    return None # too bad, standard user

if __name__ == '__main__': # unit test
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    # run(API, 'fuck') # exception if no agent of that name
    # to test this unit, we setup VMs (client + domain) to test the 3 cases
    print(run(API, API.agents()['agents'][0]['name']))