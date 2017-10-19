import json
import time
import requests
from .exceptions import *

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class admin(object):
    """Administrative functions"""

    def _login(self):
        """
        Obtain a token from the server for future requests
        \n:return: Token
        """
        login_url = '/api/admin/login'
        full_url = self._url_builder_no_token(login_url)
        resp = methods.post(full_url, self.sess, data={'username': self.uname, 'password': self.passwd})
        login_token_dict = resp.json()
        return login_token_dict['token']

    def getPermToken(self):
        """
        Get the permanent token for the server
        \n:return: Permanent token
        """
        perm_token_url = '/api/admin/permanenttoken'
        return utilties._getURL(self, perm_token_url)

    def shutdownServer(self):
        """
        Shutdown the rest server
        \n:return: dict
        """
        shutdown_url = '/api/admin/shutdown'
        return utilties._getURL(self, shutdown_url)
        # full_url = self._url_builder(shutdown_url)
        # resp = methods.get(full_url, self.sess)
        # return resp.json()

    def restartServer(self):
        """
        Restart RESTFul server
        \n:return: dict
        """
        restart_url = '/api/admin/restart'
        return utilties._getURL(self, restart_url)
        # full_url = self._url_builder(restart_url)
        # resp = methods.get(full_url, self.sess)
        # return resp.json()

class utilties(object):
    """Utility HTTP methods"""

    def check_version(self):
        """
        Check the version of Empire
        \n:param token: Token for authentication
        \n:return: Version number
        \n:return type: dict
        """
        version_url = '/api/version'
        return self._getURL(version_url)
        # full_url = self._url_builder(version_url)
        # resp = methods.get(full_url, self.sess)
        # return resp.json()

    def getMap(self):
        """
        Get API map from server.
        \n:return: dict
        """
        map_url = '/api/map'
        return self._getURL(map_url)
        # full_url = self._url_builder(map_url)
        # resp = methods.get(full_url, self.sess)
        # return resp.json()

    def getConfig(self):
        """
        Get configuration of current server
        \n:return: dict
        """
        config_url = '/api/config'
        return self._getURL(config_url)
        # full_url = self._url_builder(config_url)
        # resp = methods.get(full_url, self.sess)
        # return resp.json()

    def getCreds(self):
        """
        Get the credentials stored in the database
        \n:return: dict
        """
        full_url = '/api/creds'
        return self._getURL(full_url)

    def _checkToken(self):
        """
        Check if the token provided is authentic
        \n:param token: Token provided
        \n:return: bool
        """
        # Check the version of Empire; no news is good news.
        resp = utilties.check_version(self)

    def _getURL(self, url):
        """
        Base for simple GET requests
        \n:param url:
        \n:return:
        """
        full_url = self._url_builder(url)
        resp = methods.get(full_url, self.sess)
        return resp.json()

    def _postURL(self, url, payload=None):
        """
        Base for simple GET requests
        \n:param url:
        \n:param data:
        \n:rtype: dict
        """
        full_url = self._url_builder(url)
        resp = methods.post(full_url, self.sess, data=payload)
        return resp.json()

    def _delURL(self, url):
        """
        Make DELETE request
        \n:param url:
        \n:rtype: dict
        """
        full_url = self._url_builder(url)
        resp = methods.del_req(full_url, self.sess)
        return resp.json()

class reporting(object):
    """Class to hold all the report endpoints"""

    def report(self):
        """
        Return all logged events
        \n:return: dict
        """
        full_url = '/api/reporting'
        return utilties._getURL(self, full_url)

    def report_agent(self, agent_id):
        """
        Get all logged events for a specific agent
        \n:param agent_id: Agent name
        \n:type agent_id: str
        \n:return: dict
        """
        full_url = '/api/reporting/agent/{}'.format(agent_id)
        return utilties._getURL(self, full_url)

    def report_type(self, type_id):
        """
        Get all logged events of a specific type. Only accept event types named: checkin, task, result, rename
        \n:param type_id: Event type as string
        \n:type type_id: str
        \n:return: dict
        """
        valid_type = ['checkin', 'task', 'result', 'rename']
        if type_id in valid_type:
            full_url = '/api/reporting/type/{}'.format(type_id)
            return utilties._getURL(self, full_url)
        else:
            raise InvalidLoggingType('The event type {} does not exist.'.format(type_id)) from None

    def report_msg(self, msg_str):
        """
        Return all logged events matching message Z, wildcards accepted
        \n:param msg_str: Message to search for
        \n:type msg_str: str
        \n:return: dict
        """
        full_url = '/api/reporting/msg/{}'.format(msg_str)
        return utilties._getURL(self, full_url)

class stagers(object):

    def get_stagers(self):
        """
        Return all current stagers
        \n:return: dict
        """
        full_url = '/api/reporting'
        return utilties._getURL(self, full_url)

    def get_stager_by_name(self, name):
        """
        Get stager by name
        \n:param name: Name of stager to return
        \n:return: dict
        """
        full_url = '/api/stagers/{}'.format(name)
        return utilties._getURL(self, full_url)

    def gen_stager(self, StagerName, listener, **kwargs):
        """
        Generate a stager
        \n:param StagerName: Name of stager to call
        \n:param Listener: Name of valid listener
        \n:param kwargs: Other options
        \n:return: dict
        """
        full_url = '/api/stagers'
        full_url = self._url_builder(full_url)
        payload = {'Listener': listener, 'StagerName': StagerName}
        return methods.post(full_url, self.sess, data=payload).json()

class modules(object):

    def modules(self):
        """
        All current modules
        \n:return:
        """
        full_url = '/api/modules'
        return utilties._getURL(self, full_url)

    def module_by_name(self, name):
        """
        Return all modules with specified name
        \n:param name: Name of stager
        \n:return: dict
        """
        full_url = '/api/modules/{}'.format(name)
        return utilties._getURL(self, full_url)

    def module_exec(self, name, options):
        """
        Execute the given module with the specified options
        Requires Agent to be in options

        \n:param options: Dictionary of module options
        \n:type options: dict
        \n:rtype: dict
        """
        full_url = '/api/modules/{}'.format(name)
        return utilties._postURL(self, full_url, options)

    def module_search(self, srch_str):
        """
        Search modules for passed term
        \n:param srch_str: Search term
        \n:type srch_str: str
        \n:rtype: dict
        """
        full_url = '/api/modules/search'
        data = {'term': srch_str}
        return utilties._postURL(self, full_url, data)

    def module_search_name(self, mod_name):
        """
        Searches module names for a specific term
        \n:rtype name: str
        \n:rtype: dict
        """
        # Takes {'term':'desc'}
        full_url = '/api/modules/search/modulename'
        data = {'term': mod_name}
        return utilties._postURL(self, full_url, data)

    def module_search_desc(self, desc):
        """
        Searches module descriptions for a specific term
        \n:rtype desc: str
        \n:rtype: dict
        """
        # Takes {'term':'desc'}
        full_url = '/api/modules/search/description'
        data = {'term': desc}
        return utilties._postURL(self, full_url, data)

    def module_search_comment(self, comment):
        """
        Searches module comments for a specific term
        \n:type comment: str
        \n:rtype: dict
        """
        # Takes {'term':'desc'}
        full_url = '/api/modules/search/comments'
        data = {'term': comment}
        return utilties._postURL(self, full_url, data)

    def module_search_author(self, author):
        """
        Searches module authors for a specific term
        \n:type author: str
        \n:return:
        """
        full_url = '/api/modules/search/author'
        data ={'term': author}
        return utilties._postURL(self, full_url, data)

class agents(object):

    def agents(self):
        """
        Return a list of all agents
        \n:return: dict
        """
        full_url = '/api/agents'
        return utilties._getURL(self, full_url)

    def agents_stale(self):
        """
        Return a list of stale agents
        \n:rtype: dict
        """
        full_url = '/api/agents/stale'
        return utilties._getURL(self, full_url)

    def agents_del_stale(self):
        """
        Delete stale agents
        \n:rtype: dict
        """
        full_url = '/api/agents/stale'
        return utilties._delURL(self, full_url)

    def agents_remove(self, name):
        """
        Remove agents from database
        \n:rtype: dict
        """
        full_url = '/api/agents/{}'.format(name)
        return utilties._delURL(self, full_url)

    def agent_info(self, name):
        """
        Returns JSON describing the agent specified by name.
        \n:param name:
        \n:rtype: dict
        """
        full_url = '/api/agents/{}'.format(name)
        return utilties._getURL(self, full_url)

    def agent_shell_buffer(self, agent_name):
        """
        Return tasking results for the agent
        \n:param agent_name: Agent name as string
        \n:rtype: dict
        """
        final_url = '/api/agents/{}/results'.format(agent_name)
        return utilties._getURL(self, final_url)

    def agent_run_shell_cmd(self, agent_name, options):
        """
        Task agent to run shell commdn
        \n:param agent_name: Agent name
        \n:param options: Dict of command
        \n:rtype: dict
        """
        final_url = '/api/agents/{}/shell'.format(agent_name)
        return utilties._postURL(self, final_url, payload=options)
    
    def agent_upload(self, agent_name, options):
        """
        Task agent to upload { "filename":"fullpath", "data":BASE64encodedcontent}
        \n:param agent_name: Agent name
        \n:param options: Dict of command
        \n:rtype: dict
        """
        final_url = '/api/agents/{}/upload'.format(agent_name)
        return utilties._postURL(self, final_url, payload=options)

    def agent_run_shell_cmd_with_result(self, agent_name, options, timeout=120):
        """
        Task agent to run shell commdn with results returned directly
        \n:param agent_name: Agent name
        \n:param options: Dict of command
        \n:rtype: dict
        """
        self.agent_clear_results(agent_name)
        r = self.agent_run_shell_cmd(agent_name, options)
        return self.agent_get_results(agent_name, r['taskID'], timeout)

    def agent_rename(self, current_name, new_name):
        """
        Renames the specified agent
        \n:param current_name:
        \n:param new_name:
        \n:return:
        """
        # Takes {'newname':'NAME'}
        final_url = '/api/agents/{}/rename'.format(current_name)
        options = {'newname': 'new_name'}
        return utilties._postURL(self, final_url, payload=options)

    def agent_clear_buff(self, name):
        """
        Clears the tasking buffer for the specified agent
        \n:rtype: dict
        """
        final_url = '/api/agents/{}/clear'.format(name)
        return utilties._getURL(self, final_url)
    
    def agent_kill(self, name):
        """
        Tasks the specified agent to exit
        \n:rtype: dict
        """
        final_url = '/api/agents/{}/kill'.format(name)
        return utilties._getURL(self, final_url)
    
    def agent_clear_results(self, name):
        final_url = '/api/agents/{}/results'.format(name)
        return utilties._delURL(self, final_url)

    def agent_get_results(self, agent_name, task_id, time_out=120):
        """
        Return task results for the agent
        \n:param agent_name: Agent name as string
        \n:param task_id: task ID from agent tasking
        \n:rtype: str or None if failed
        """
        final_url = '/api/agents/{}/results'.format(agent_name)
        while time_out > 0:
            r = utilties._getURL(self, final_url)
            resultstr = ''
            for result in r['results']:
                for ar in result['AgentResults']:
                    if(len(ar) > 0 and ar not in resultstr):
                        resultstr += ar
                    if('Job' in resultstr and 'completed' in resultstr):
                        return resultstr
                    else:
                        if(len(resultstr) > 0):
                            return resultstr
            time.sleep(1)
            time_out -= 1
        return None

    def agent_get_name(self, hostname_or_ipaddr, high_integrity=False):
        """
        Return agent name given hostname or ip address.
        Empty string if not found.
        \n:param hostname_or_ipaddr: Host name or IP address string
        \n:rtype: string
        """
        agent_name = ""
        r = self.agents()
        if len(r['agents']) == 0: 
            return agent_name
        for agent in r['agents']:
            if (hostname_or_ipaddr.lower() in str(agent).lower()):
                if agent['high_integrity'] == 0 and high_integrity is False:
                    return agent['name']
                elif agent['high_integrity'] > 0 and high_integrity is True:
                    return agent['name']
                continue

        return agent_name

class listeners(object):

    def listeners(self):
        """
        Return a list of all listeners
        \n:return: dict
        """
        full_url = '/api/listeners'
        return utilties._getURL(self, full_url)

    def listeners_get_first(self):
        """
        Return name of the first listener
        \n:return type: str or None if no listeners
        """
        ls = self.listeners()
        if len(ls['listeners']) == 0:
            raise ValueError('no listeners')
        else:
            return ls['listeners'][0]['name']
    
    def listeners_exist(self, name):
        """
        Return true give listener name exists
        \n:return type: boolean
        :raise error: if there are no listeners
        """
        ls = self.listeners()
        if name in str(ls):
            return True
        else:
            return False

class empireAPI(utilties, admin, reporting, stagers, modules, agents, listeners):

    def __init__(self, host, port=1337, verify=False, token=None, uname=None, passwd=None):
        """
        Information for the start of the class. You must include either a token or a username and password
        \n:param host: IP or domain name to connect to
        \n:param port: Port to connect to
        \n:param verify: Requests verify the SSL chain
        \n:param token: Token to authenticate with
        \n:param uname: Username to authenticate with
        \n:param passwd: Password to authenticate with
        """

        # No parameters provided
        if token is None and uname is None and passwd is None:
            raise NoAuthenticationProvided('No authentication was provided.')
        elif token is None and (uname is None or passwd is None): # Either uname or passwd but not both and no token
            raise NoAuthenticationProvided('Incomplete authentication provided.')

        # Check if host starts with 'https://' or 'http://'
        if not (host.startswith('https://') or host.startswith('http://')):
            # Append 'https:// to the beginning of the host
            host = 'https://{}'.format(host)


        self.host = host
        self.port = port
        self.verify = verify
        self.token = token
        self.uname = uname
        self.passwd = passwd
        # We should have all of the information needed now to open a connection

        # Other variables to use
        self.perm_token = None
        # Create the session for Requests and consistency
        self.sess = requests.Session()
        self.sess.verify = False
        self.sess.headers = {'Content-Type': 'application/json'}

        # If token is provided, check the version to make sure it works
        if token is not None:
            self._checkToken()
        else:
            # If username and password are provided, get a token
            self.token = admin._login(self)

    def _url_builder(self, resource_location):
        """
        Builds the complete URI
        \n:param resource_location: Leading slash all the way to but not including the ?
        \n:return: URI in a string.
        """
        url = '{base}:{port}{location}?token={token}'.format(base=self.host, port=self.port,
                                                              location=resource_location, token=self.token)
        return url

    def _url_builder_no_token(self, resource_location):
        """
        Builds a URL without a token parameter at the end
        \n:param resource_location: Leading slash all the way to but not including the ?
        \n:return: URI in a string.
        """
        return '{base}:{port}{location}'.format(base=self.host, port=self.port, location=resource_location)
    
    def module_exec_with_result(self, module_path, options, agent_name, timeout=120):
        """
        Execute the given module with the specified options
        Requires Agent to be in options
        \n:param module_path: module path string
        \n:param options: Dictionary of module options
        \n:param agent_name: agent name string
        \n:param timeout: time out in seconds integer
        \n:rtype: dict
        """
        self.agent_clear_results(agent_name)
        r = self.module_exec(module_path, options)
        return self.agent_get_results(agent_name, r['taskID'], timeout)

class methods:
    """All HTTP methods in use"""

    @staticmethod
    def httpErrors(resp):
        status_code = resp.status_code

        if status_code == 400:
            # Bad Request
            raise HTTPError.BadRequest(resp.json()['error']) from None
        elif status_code == 401:
            # Unauthorized
            raise HTTPError.UnAuthorized(resp.json()['error']) from None
        elif status_code == 405:
            raise HTTPError.MethodNotAllowed(resp.json()['error']) from None
        elif status_code != 200:
            raise HTTPError.UnKnownHTTPError(resp.json()['error']) from None

    @staticmethod
    def get(url, sess):
        """Make a GET request"""
        r = sess.get(url)
        # Check for errors
        methods.httpErrors(r)

        # No news is good news
        return r

    @staticmethod
    def post(url, sess, data=None):
        """Make a POST request"""

        # dumps is there to ensure the data is properly formatted
        r = sess.post(url, data=json.dumps(data))
        # Check for errors
        methods.httpErrors(r)

        # No news is good news
        return r

    @staticmethod
    def del_req(url, sess):
        """Make DELETE request"""
        r = sess.delete(url)
        # Check for errors
        methods.httpErrors(r)

        # No news is good news
        return r