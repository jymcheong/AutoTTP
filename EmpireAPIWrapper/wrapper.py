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
        :return: Token
        """
        login_url = '/api/admin/login'
        full_url = self._url_builder_no_token(login_url)
        resp = methods.post(full_url, self.sess, data={'username': self.uname, 'password': self.passwd})
        login_token_dict = resp.json()
        return login_token_dict['token']

    def getPermToken(self):
        """
        Get the permanent token for the server
        :return: Permanent token
        """
        perm_token_url = '/api/admin/permanenttoken'
        return utilties._getURL(self, perm_token_url)

    def shutdownServer(self):
        """
        Shutdown the rest server
        :return: dict
        """
        shutdown_url = '/api/admin/shutdown'
        return utilties._getURL(self, shutdown_url)
        # full_url = self._url_builder(shutdown_url)
        # resp = methods.get(full_url, self.sess)
        # return resp.json()

    def restartServer(self):
        """
        Restart RESTFul server
        :return: dict
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
        :param token: Token for authentication
        :return: Version number
        :return type: dict
        """
        version_url = '/api/version'
        return self._getURL(version_url)
        # full_url = self._url_builder(version_url)
        # resp = methods.get(full_url, self.sess)
        # return resp.json()

    def getMap(self):
        """
        Get API map from server.
        :return: dict
        """
        map_url = '/api/map'
        return self._getURL(map_url)
        # full_url = self._url_builder(map_url)
        # resp = methods.get(full_url, self.sess)
        # return resp.json()

    def getConfig(self):
        """
        Get configuration of current server
        :return: dict
        """
        config_url = '/api/config'
        return self._getURL(config_url)
        # full_url = self._url_builder(config_url)
        # resp = methods.get(full_url, self.sess)
        # return resp.json()

    def getCreds(self):
        """
        Get the credentials stored in the database
        :return: dict
        """
        full_url = '/api/creds'
        return self._getURL(full_url)

    def _checkToken(self):
        """
        Check if the token provided is authentic
        :param token: Token provided
        :return: bool
        """
        # Check the version of Empire; no news is good news.
        resp = utilties.check_version(self)

    def _getURL(self, url):
        """
        Base for simple GET requests
        :param url:
        :return:
        """
        full_url = self._url_builder(url)
        resp = methods.get(full_url, self.sess)
        return resp.json()

    def _postURL(self, url, payload=None):
        """
        Base for simple GET requests
        :param url:
        :param data:
        :rtype: dict
        """
        full_url = self._url_builder(url)
        resp = methods.post(full_url, self.sess, data=payload)
        return resp.json()

    def _delURL(self, url):
        """
        Make DELETE request
        :param url:
        :rtype: dict
        """
        full_url = self._url_builder(url)
        resp = methods.del_req(full_url, self.sess)
        return resp.json()

class reporting(object):
    """Class to hold all the report endpoints"""

    def report(self):
        """
        Return all logged events
        :return: dict
        """
        full_url = '/api/reporting'
        return utilties._getURL(self, full_url)

    def report_agent(self, agent_id):
        """
        Get all logged events for a specific agent
        :param agent_id: Agent name
        :type agent_id: str
        :return: dict
        """
        full_url = '/api/reporting/agent/{}'.format(agent_id)
        return utilties._getURL(self, full_url)

    def report_type(self, type_id):
        """
        Get all logged events of a specific type. Only accept event types named: checkin, task, result, rename
        :param type_id: Event type as string
        :type type_id: str
        :return: dict
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
        :param msg_str: Message to search for
        :type msg_str: str
        :return: dict
        """
        full_url = '/api/reporting/msg/{}'.format(msg_str)
        return utilties._getURL(self, full_url)

class stagers(object):

    def get_stagers(self):
        """
        Return all current stagers
        :return: dict
        """
        full_url = '/api/reporting'
        return utilties._getURL(self, full_url)

    def get_stager_by_name(self, name):
        """
        Get stager by name
        :param name: Name of stager to return
        :return: dict
        """
        full_url = '/api/stagers/{}'.format(name)
        return utilties._getURL(self, full_url)

    def gen_stager(self, StagerName, listener, **kwargs):
        """
        Generate a stager
        :param StagerName: Name of stager to call
        :param Listener: Name of valid listener
        :param kwargs: Other options
        :return: dict
        """
        full_url = '/api/stagers'
        full_url = self._url_builder(full_url)
        payload = {'Listener': listener, 'StagerName': StagerName}
        return methods.post(full_url, self.sess, data=payload).json()

class modules(object):

    def modules(self):
        """
        All current modules
        :return:
        """
        full_url = '/api/modules'
        return utilties._getURL(self, full_url)

    def module_by_name(self, name):
        """
        Return all modules with specified name
        :param name: Name of stager
        :return: dict
        """
        full_url = '/api/modules/{}'.format(name)
        return utilties._getURL(self, full_url)

    def module_exec(self, name, options):
        """
        Execute the given module with the specified options
        Requires Agent to be in options

        :param options: Dictionary of module options
        :type options: dict
        :rtype: dict
        """
        full_url = '/api/modules/{}'.format(name)
        return utilties._postURL(self, full_url, options)

    def module_search(self, srch_str):
        """
        Search modules for passed term
        :param srch_str: Search term
        :type srch_str: str
        :rtype: dict
        """
        full_url = '/api/modules/search'
        data = {'term': srch_str}
        return utilties._postURL(self, full_url, data)

    def module_search_name(self, mod_name):
        """
        Searches module names for a specific term
        :rtype name: str
        :rtype: dict
        """
        # Takes {'term':'desc'}
        full_url = '/api/modules/search/modulename'
        data = {'term': mod_name}
        return utilties._postURL(self, full_url, data)

    def module_search_desc(self, desc):
        """
        Searches module descriptions for a specific term
        :rtype desc: str
        :rtype: dict
        """
        # Takes {'term':'desc'}
        full_url = '/api/modules/search/description'
        data = {'term': desc}
        return utilties._postURL(self, full_url, data)

    def module_search_comment(self, comment):
        """
        Searches module comments for a specific term
        :type comment: str
        :rtype: dict
        """
        # Takes {'term':'desc'}
        full_url = '/api/modules/search/comments'
        data = {'term': comment}
        return utilties._postURL(self, full_url, data)

    def module_search_author(self, author):
        """
        Searches module authors for a specific term
        :type author: str
        :return:
        """
        full_url = '/api/modules/search/author'
        data ={'term': author}
        return utilties._postURL(self, full_url, data)

class agents(object):

    def agents(self):
        """
        Return a list of all agents
        :return: dict
        """
        full_url = '/api/agents'
        return utilties._getURL(self, full_url)

    def agents_stale(self):
        """
        Return a list of stale agents
        :rtype: dict
        """
        full_url = '/api/agents/stale'
        return utilties._getURL(self, full_url)

    def agents_del_stale(self):
        """
        Delete stale agents
        :rtype: dict
        """
        full_url = '/api/agents/stale'
        return utilties._delURL(self, full_url)

    def agents_remove(self, name):
        """
        Remove agents from database
        :rtype: dict
        """
        full_url = '/api/agents/{}'.format(name)
        return utilties._delURL(self, full_url)

    def agent_info(self, name):
        """
        Returns JSON describing the agent specified by name.
        :param name:
        :rtype: dict
        """
        full_url = '/api/agents/{}'.format(name)
        return utilties._getURL(self, full_url)

    def agent_shell_buffer(self, agent_name):
        """
        Return tasking results for the agent
        :param agent_name: Agent name as string
        :rtype: dict
        """
        final_url = '/api/agents/{}/results'.format(agent_name)
        return utilties._getURL(self, final_url)

    def agent_run_shell_cmd(self, agent_name, options):
        """
        Task agent to run shell commdn
        :param agent_name: Agent name
        :param options: Dict of command
        :rtype: dict
        """
        final_url = '/api/agents/{}/shell'.format(agent_name)
        return utilties._postURL(self, final_url, payload=options)

    def agent_rename(self, current_name, new_name):
        """
        Renames the specified agent
        :param current_name:
        :param new_name:
        :return:
        """
        # Takes {'newname':'NAME'}
        final_url = '/api/agents/{}/rename'.format(current_name)
        options = {'newname': 'new_name'}
        return utilties._postURL(self, final_url, payload=options)

    def agent_clear_buff(self, name):
        """
        Clears the tasking buffer for the specified agent
        :rtype: dict
        """
        final_url = '/api/agents/{}/clear'.format(name)
        return utilties._getURL(self, final_url)

    def agent_kill(self, name):
        """
        Tasks the specified agent to exit
        :rtype: dict
        """
        final_url = '/api/agents/{}/kill'.format(name)
        return utilties._getURL(self, final_url)

    def agent_get_results(self, agent_name, task_id, time_out=120):
        """
        Return tasking results for the agent
        :param agent_name: Agent name as string
        :param task_id: task ID from agent tasking
        :rtype: str or None if failed
        """
        final_url = '/api/agents/{}/results'.format(agent_name)
        result = None
        while True:
            r = utilties._getURL(self, final_url)
            for result in r['results']:
                if task_id == result['taskID']:
                    if not result['results'].startswith('Job') or ('\n' in result['results']): 
                        return result['results']
            time.sleep(1)
            time_out -= 1
        
        return result

    def agent_get_name(self, hostname_or_ipaddr, high_integrity=False):
        """
        Return agent name given hostname or ip address.
        Empty string if not found.
        :param hostname_or_ipaddr: Host name or IP address string
        :rtype: string
        """
        agent_name = ""
        r = self.agents()
        if len(r['agents']) == 0: 
            return agent_name
        for agent in r['agents']:
            if agent['hostname'].lower()    == hostname_or_ipaddr.lower() or \
               agent['external_ip'].lower() == hostname_or_ipaddr.lower() or \
               agent['internal_ip'].lower() == hostname_or_ipaddr.lower():
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
        :return: dict
        """
        full_url = '/api/listeners'
        return utilties._getURL(self, full_url)

    def listeners_get_first(self):
        """
        Return name of the first listener
        :return type: str or None if no listeners
        """
        ls = self.listeners()
        if len(ls['listeners']) == 0:
            raise ValueError('no listeners')
        else:
            return ls['listeners'][0]['name']
    
    def listeners_exist(self, name):
        """
        Return true give listener name exists
        :return type: boolean
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
        :param host: IP or domain name to connect to
        :param port: Port to connect to
        :param verify: Requests verify the SSL chain
        :param token: Token to authenticate with
        :param uname: Username to authenticate with
        :param passwd: Password to authenticate with
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
        :param resource_location: Leading slash all the way to but not including the ?
        :return: URI in a string.
        """
        url = '{base}:{port}{location}?token={token}'.format(base=self.host, port=self.port,
                                                              location=resource_location, token=self.token)
        return url

    def _url_builder_no_token(self, resource_location):
        """
        Builds a URL without a token parameter at the end
        :param resource_location: Leading slash all the way to but not including the ?
        :return: URI in a string.
        """
        return '{base}:{port}{location}'.format(base=self.host, port=self.port, location=resource_location)

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