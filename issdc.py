import requests
import re
import interval
import logging

BASE_URL = 'https://pradan.issdc.gov.in'
PAYLOAD_VISIT_URL = f'{BASE_URL}/ch2/protected/payload.xhtml'

class ISSDCRequester:
  def __init__(self, username, password, keep_alive_interval=600):
    self.username = username
    self.password = password
    self.request_session = None
    self.keep_alive_interval = keep_alive_interval
    self.interval_thread = None

  def __auth(self):
    """
    INTERNAL METHOD
    Complete the auth flow on the issdc site. Return a dictionary-like object of cookies.
    An exception will be raised if the authorization fails.
    """

    # Close any current session on new auth
    self.close()

    # Create a session to carry headers/cookies across requests
    # This session should also handle keep alive pings
    self.request_session = requests.session()

    headers = {'User-Agent': 'Mozilla/5.0'}
    # initial_visit_url = 'https://pradan.issdc.gov.in/ch2/'
    payload_visit_res = self.request_session.get(
      PAYLOAD_VISIT_URL,
      headers=headers,
      allow_redirects=True)

    logging.info(f'Payload visit status: {payload_visit_res.status_code}')

    auth_url_regex = re.compile('<form.*action=\"(https://idp\\.issdc\\.gov\\.in/auth.*?)\"')
    auth_url_match = auth_url_regex.search(payload_visit_res.text)
    if auth_url_match == None:
      raise Exception("Unable to find auth URL")

    auth_url = auth_url_match.group(1).replace('&amp;', '&')
    logging.info(f'Aquired auth URL: {auth_url}')

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
      logging.info("Hackerman: I'm in 😎")
      return auth_res.cookies
    else:
      raise Exception('Failed final login step, incorrect status code:', auth_res.status_code)

  def __keep_alive(self):
    """
    Send the "keep alive" request to the issdc server.
    """
    payload_visit_res = self.request_session.get(PAYLOAD_VISIT_URL)
    logging.info(f'Keep alive payload visit status: {payload_visit_res.status_code}')

  def refresh(self):
    """
    Refresh issdc authorization.
    If threading, this should not be called during an ongoing request as the original auth tokens will be invalidated and the request will fail.
    """
    self.cookies = self.__auth()

    # Spawn a thread with a keep-alive signal.
    # This keep-alive extends the life of the authorization and is not the same as the automatic keep-alive provided by the session.
    self.interval_thread = interval.SetInterval(self.__keep_alive, self.keep_alive_interval)

  def request(self, method, url, **kwargs):
    """
    Perform a request.
    This function wraps the 'requests' library signature and injects cookies required for authorization.
    If there is no active session, one will be created.
    """
    # NOTE: If session was already defined check for an unauthorized response on initial request and trigger an automatic refresh/retry
    if self.request_session == None:
      self.refresh()
    return self.request_session.request(method, url, cookies=self.cookies, **kwargs)

  def request_path(self, method, path, **kwargs):
    """
    Perform a request with a path from BASE_URL.
    """
    return self.request(method, f'{BASE_URL}{path}', **kwargs)

  def close(self):
    """
    Close the current session and clear auth data.
    """
    if self.request_session != None:
      self.request_session.close()
      self.request_session = None
    if self.interval_thread != None:
      self.interval_thread.stop()
      self.interval_thread = None
    self.cookies = None
