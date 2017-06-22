from crawler import Crawler
from downloaders import LazyDownloader
from urlparse import urlparse
import sys

AGGREGATOR_NAME = "manual"
AGGREGATOR_URL = "N/A"


class ManualCrawler(Crawler):
    downloader = None
    curpage = 0

    def __init__(self, download_dir, limit):
        super(ManualCrawler, self).__init__(AGGREGATOR_NAME, AGGREGATOR_URL, download_dir=download_dir, limit=limit)
        self.downloader = LazyDownloader(0, 0, self.s, self.l)
        self.curpage=0

    def crawl(self, session):
        links = []
        while 1:
            try:
                # Just ask for the download URL
                print("URL (or empty line for quitting): ")
                url = sys.stdin.readline()
                url = url.strip()
                if url == '':
                    break
                # Check if that is a valid URL.
                urlparse(url)

                #Add the link to the output
                links.append(url)
            except:
                self.l.exception("Error!")

        if len(links) == 0:
            return None
        else:
            return links

if __name__ == "__main__":
    limit, outputdir = Crawler.parse_args(sys.argv[1:],AGGREGATOR_NAME)
    c = ManualCrawler(download_dir=outputdir, limit=limit)
    c.start()
