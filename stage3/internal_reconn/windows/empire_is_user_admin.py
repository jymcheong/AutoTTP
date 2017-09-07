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
    :param API: EmpireAPIWrapper object
    :param agent_name: name of agent
    :return type: str or None
    """
    agent_details = API.agent_info(agent_name)['agents'][0]
    # either local/domain user, still check if user is in local administrators
    opts = {'Agent': agent_name, 'command': 'net localgroup Administrators'}
    r = API.agent_run_shell_cmd(agent_name, opts)
    localadmin_query_result = API.agent_get_results(agent_name, r['taskID'])    
    if localadmin_query_result is None:
        raise ValueError('fail to run "net localgroup Administrator", check empire console')
    
    # first case: for a local user (will always be host\username), check if s/he is local admin group
    if agent_details['hostname'] in agent_details['username']: 
        target_username = agent_details['username'].replace(agent_details['hostname']+'\\', "")
        if target_username in localadmin_query_result:
            return "Local"
    else: # 2nd case, for a domain user, we return the higher privilege group ie. Domain
        target_username = agent_details['username'].split('\\')[1]
        # options for the module, required options are prefixed
        opts = situational_awareness.network_powerview_get_group.options
        r = API.module_exec(situational_awareness.network_powerview_get_group.path, \
                            { opts.username: target_username,
                              opts.required_agent: agent_name})
        # there are other types of admin eg. Enterprise, Schema Admin...
        if 'Admin' in API.agent_get_results(agent_name, r['taskID']): 
            return 'Domain'
        # 3rd case, a domain user could be added to local admin group
        if agent_details['username'] in localadmin_query_result:
            return 'Local'
    return None # too bad, standard user

if __name__ == '__main__': # unit test
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    # run(API, 'fuck') # exception if no agent of that name
    # to test this unit, we setup VMs (client + domain) to test the 3 cases
    print(run(API, '3LNCZ41M'))