import requests
import re

BASE_URL = 'https://pradan.issdc.gov.in'

class ISSDCRequester:
  def __init__(self, username, password):
    self.username = username
    self.password = password
    self.request_session = None

  def __auth(self):
    # Close any current session on new auth
    self.close()

    # Create a session to carry headers/cookies across requests
    # This session should also handle keep alive pings
    self.request_session = requests.session()

    headers = {'User-Agent': 'Mozilla/5.0'}
    # initial_visit_url = 'https://pradan.issdc.gov.in/ch2/'
    payload_visit_url = f'{BASE_URL}/ch2/protected/payload.xhtml'
    payload_visit_res = self.request_session.get(
      payload_visit_url,
      headers=headers,
      allow_redirects=True)

    print('Payload visit status:', payload_visit_res.status_code)

    auth_url_regex = re.compile('<form.*action=\"(https://idp\\.issdc\\.gov\\.in/auth.*?)\"')
    auth_url_match = auth_url_regex.search(payload_visit_res.text)
    if auth_url_match == None:
      raise Exception("Unable to find auth URL")

    auth_url = auth_url_match.group(1).replace('&amp;', '&')
    print('Aquired auth URL:', auth_url)

    # Store cookies for next request
    cookies = requests.utils.cookiejar_from_dict(requests.utils.dict_from_cookiejar(self.request_session.cookies))

    # Refusing the redirect is important here
    # When redirected the server expects your cookie to be set on your non-existent client
    auth_res = self.request_session.post(
      auth_url,
      headers=headers,
      data={'username': self.username, 'password': self.password},
      cookies=cookies,
      allow_redirects=False)

    if auth_res.status_code == 302:
      print('Auth successful')
      return auth_res.cookies
    else:
      raise Exception('Failed final login step, incorrect status code:', auth_res.status_code)

  def refresh(self):
    self.cookies = self.__auth()

  def request(self, method, url, **kwargs):
    # NOTE: If session was already defined check for an unauthorized response on initial request and trigger an automatic refresh/retry
    if self.request_session == None:
      self.refresh()
    return self.request_session.request(method, url, cookies=self.cookies, **kwargs)

  def request_path(self, method, path, **kwargs):
    return self.request(method, f'{BASE_URL}{path}', **kwargs)

  def close(self):
    if self.request_session != None:
      self.request_session.close()
