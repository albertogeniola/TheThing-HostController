# This class represents a basic crawler.
# Its funcitonalities are extended by sub classes.
import abc
import datetime
import getopt
import hashlib
import logging
import ntpath
import os
import posixpath
import shutil
import sys
import tempfile
import time
import urlparse

import requests
from logic import db

from HostController.settings import CFG
from utils import is_win32, is_msi

MAX_RETRIES = 3
LIMIT = 200
TO=20

class Crawler(object):
    __metaclass__ = abc.ABCMeta
    s = requests.Session()

    # Name of the crawler
    name = None

    # Represents the destination directory for crawled files
    download_dir = None
    limit = None
    aggregator_id = None

    additional_headers = None

    # Logger
    l = None

    def __init__(self, aggregator_name, aggregator_url, download_dir, limit, additional_headers=None):
        self.name = aggregator_name
        self.aggregator_id = db.JobManager().get_or_create_aggregator(aggregator_name, aggregator_url).id
        logging.getLogger("requests").setLevel(logging.WARNING)
        self.l = logging.getLogger("crawler_" + aggregator_name)
        fh = logging.FileHandler("crawler_" + aggregator_name+'.log')
        self.l.setLevel(logging.DEBUG)
        self.l.addHandler(fh)

        self.download_dir = download_dir
        self.limit = limit

        # Basic headers
        # We need to emulate an user agent...
        if additional_headers is not None:
            self.additional_headers = additional_headers


    def _download(self, url):
        """
        Downloads a file given its URL and returns a tuple, containing the path to the downloaded file, its md5
        and a guessed name for that file.
        :param url:
        :return:
        """
        self.l.debug("Downloading: %s" % url)
        resp = None
        try:
            # First retrieve only headers.
            resp = self.s.head(url, verify=False, timeout=TO, allow_redirects=True, headers=self.additional_headers)
            if resp.status_code != 200:
                raise Exception("Cannot retrieve download link from %s. Response code was %d." % (resp.url, resp.status_code))

            # Guess the file name from the ContentDisposition header, if any. Otherwise fall back to the URL parse
            fname = ""
            if 'Content-Disposition' in resp.headers:
                tmp = resp.headers['Content-Disposition'].split('filename=')
                if len(tmp)>1:
                    fname = tmp[1]

            if fname == "":
                path = urlparse.urlsplit(resp.url).path
                fname = posixpath.basename(path)

            if fname is None or fname == '':
                # We cannot accept files with invalid extension. Refuse it.
                self.l.debug("Refusing file with unknown name")
                return None, None, None, None
            else:
                fname = self.purge_quotes(fname)
                # Immediately verify if the given file is neither .exe nor .msi
                exts = os.path.splitext(fname)
                if len(exts)>1 and (exts[1].lower() != ".exe" and exts[1].lower() != ".msi"):
                    # The extension is unknown for us. Skip this file.
                    self.l.debug("Refusing file with unvalid extension: %s" % fname)
                    return None, None, None
        finally:
            if resp is not None:
                resp.close()

        try:
            # Now perform the get request
            resp = self.s.get(url, verify=False, timeout=TO, allow_redirects=True,headers=self.additional_headers)
            if resp.status_code != 200:
                raise Exception("Cannot retrieve download link from %s. Response code was %d." % (resp.url, resp.status_code))

            target_size = resp.headers.get("content-length")

            t0 = datetime.datetime.utcnow()
            size = 0
            with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                # Download the file and calculate hashes in the meanwhile
                m = hashlib.md5()
                s = hashlib.sha1()
                for chunk in resp.iter_content(8192):
                    m.update(chunk)
                    s.update(chunk)
                    f.write(chunk)
                    size += len(chunk)

                    t1 = datetime.datetime.utcnow()
                    if (t1-t0).total_seconds() > 1:
                        t0 = t1
                        info = None
                        if target_size is not None:
                            percentige = float(size) * 100 / int(target_size)
                            info = "%f %%" % percentige
                        else:
                            info = "%f Mb" % (size/1024/1024)

                        print(info)

                f.flush()

            self.l.debug("Downloaded: %d bytes -> %s" % (size, f.name))

            # At this point we assume the file downloaded correctly. Return info: path of file, md5, guessed file name
            return f.name, (m.hexdigest().lower(),s.hexdigest().lower()), fname
        finally:
            if resp is not None:
                resp.close()

    def _handle_download(self, downlink, file_path, hashes, name):
        md5, sha1 = hashes

        # Here we decide if we should keep or discard the new file.
        # The db checks a similar record comparing hashes and HOSTNAME (bound to aggregator_id).
        # So we check this in advance to avoid problems.
        session = db.sessionmaker()

        fuzzy = fuzzy._fuzzy_hash_from_file(file_path).lower()

        try:
            # Refuse any non 64bit installer
            if (not is_win32(file_path)) and (not is_msi(name)):
                return

            el = session.query(db.Job).with_for_update().filter(db.Job.sha1 == sha1,
                                                                db.Job.aggregator_id == self.aggregator_id)\
                .first()

            if el is None:
                self.l.debug("Binary file %s from %s is not yet contained in the DB. Adding it." % (sha1, downlink))
                # Ok, this is a new entry. Accept the file.
                dest_path = os.path.join(self.download_dir, name)
                shutil.copy(file_path, dest_path)
                j = db.Job(fname=name,
                          aggregator_id=self.aggregator_id,
                          downlink=downlink,
                          downdate=datetime.datetime.utcnow(),
                          assigned=False,
                          path=db.translate_to_installer_path(dest_path),
                          md5=md5.lower(),
                          sha1=sha1.lower(),
                          fuzzy=fuzzy.lower())

                session.add(j)
                session.commit()
                return True
            else:
                self.l.debug("Binary file %s from %s is already contained in the DB. Skipping." % (sha1, downlink))
                # There already was something like that.
                return False

        except Exception as e:
            session.rollback()
            self.l.exception("Cannot add %s to db." % file_path)
            return False
        finally:
            session.close()
            # Remove previous one
            os.remove(file_path)

    @abc.abstractmethod
    def crawl(self, session):
        """
        This method must be implement in a way that it retuls a list of URLs to be downloaded.
        :param fill:
        :return:
        """
        pass

    def start(self):
        while True:
            links = self.crawl(self.s)
            if links is None:
                self.l.warning("Crawl() returned None. No more links to handle.")
                break

            for link in links:
                if self.limit == 0:
                    self.l.info("Limit reached. Crawler has finished.")
                    return

                path, hashes, fname = None, None, None

                failures = 0
                ok = False
                while failures < MAX_RETRIES and not ok:
                    # First step: download the file. In case of exception, retry until we fail for 3 times.
                    try:
                        path, hashes, fname = self._download(link)
                        ok = True
                    except Exception as e:
                        self.l.exception("Could not download from url %s. Attempt %d of %d." %
                                       (link, failures, MAX_RETRIES))
                        failures += 1

                if not ok:
                    # give up. We weren't able to download this file.
                    self.l.error("Failed to download from url %s." % link)
                    continue

                # There is a case in which we get an OK but the download has been skipped because
                # is not compliant for us, e.g. the file is not supported.
                if path is None:
                    continue

                # At this point we are sure something has been downloaded. Let's handle it.
                added = self._handle_download(downlink=link, file_path=path, hashes=hashes, name=fname)

                # Check if file was added. If so, decrease limit.
                if added:
                    self.l.info("Job Added!")
                    self.limit -= 1
                else:
                    self.l.warning("Job refused.")

    @staticmethod
    def purge_quotes(string):
        s = string
        if s.startswith('"'):
            s = s[1:]

        if s.endswith('"'):
            s = s[:-1]

        return s

    @staticmethod
    def usage():
        print(__name__ + ' [-l <limit>]')

    @staticmethod
    def parse_args(argv, name=None):
        download_dir = CFG.installers_base_dir

        try:
          opts, args = getopt.getopt(argv, "ho:l:", ["output-dir=", "limit="])
        except getopt.GetoptError:
          Crawler.usage()
          sys.exit(2)

        # Default value
        limit = LIMIT

        for opt, arg in opts:
            if opt == '-h':
                Crawler.usage()
                sys.exit()
            elif opt in ("-l", "--limit"):
                try:
                    limit = int(arg)
                except:
                    Crawler.usage()
                    sys.exit(4)

        # If no outputdir has been specified, crash.
        if download_dir is None:
            sys.stderr.write("Invalid or missing outputdir specified.")
            sys.exit(3)
        else:
            # Create the directory if doesn't exist
            if not ntpath.isdir(download_dir):
                os.mkdir(download_dir)

        # Create a subdir for this run
        if name is None:
            name = str(time.time())
        download_dir = os.path.join(download_dir, name)
        if not os.path.isdir(download_dir):
            os.mkdir(download_dir)

        return limit, download_dir
