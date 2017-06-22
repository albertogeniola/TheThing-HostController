import random
import time
import logging
import requests
TO = 20

# Softpedia implements some sort of download monitor. They actively ban crawlers. Thus, we need to add some "waiting"
# among sequential requests. The following class does exactly this
class LazyDownloader(object):
    min = None
    max = None
    l = None
    opener = None
    additional_headers = None

    def __init__(self, min, max, session=None, logger=None, additional_headers=None):
        self.max = max
        self.min = min
        if logger is not None:
            self.l = logger
        else:
            self.l = logging

        if session is not None:
            self.s = session
        else:
            self.s=requests.session()

        if additional_headers is not None:
            self.additional_headers=additional_headers

    def get_redirect_link(self, link):
        resp = self.s.get(link, allow_redirects=False,headers=self.additional_headers)

        # Make sure it's a 302
        if not resp.is_redirect:
            return None
        else:
            return resp.headers['Location']

    def download(self, link):
        data = ''
        pad = self.max - self.min
        banned_sleeping = pad
        resp = None

        while data == '':
            try:
                interval = random.random()*pad + self.min
                # sleep a bit
                #self.l.debug("Sleeping %f seconds in order to not get banned..." % interval)
                time.sleep(interval)

                resp = self.s.get(link, allow_redirects=True, headers=self.additional_headers)
                if resp.status_code != 200:
                    return None

                data = resp.content

                if data == '':
                    # Double the sleeping time
                    banned_sleeping *= 2
                    self.l.warning("I think i got banned... sleeping now %f" % banned_sleeping)
                    time.sleep(banned_sleeping)
                    continue
                else:
                    return data
            except Exception as e:
                self.l.exception("Error during download/request in LazyDownloader.")
                raise e
            finally:
                if resp is not None:
                    resp.close()

    def head(self, link):
        resp = None
        try:
            resp = self.s.head(link,allow_redirects=True,headers=self.additional_headers)
            if resp.status_code != 200:
                self.l.error("Download error, status code was %d when crawling %s" % (resp.status_code,link))
                return None, None

            return resp.headers, resp.url
        finally:
            if resp is not None:
                resp.close()