import sys
from lxml import etree
import logging
from crawler import Crawler
from downloaders import LazyDownloader
import urlparse

AGGREGATOR_NAME = "brothersoft"
AGGREGATOR_URL = "http://www.brothersoft.com"
MAIN_URL = "http://www.brothersoft.com/windows/top-downloads/top-freeware/"
LIST_SELECTOR = "//span[@class='tabDownload']/a"


class SoftpediaCrawler(Crawler):
    downloader = None
    curpage = 0

    def __init__(self, download_dir, limit):
        super(SoftpediaCrawler, self).__init__(AGGREGATOR_NAME, AGGREGATOR_URL, download_dir=download_dir, limit=limit)
        self.downloader = LazyDownloader(0, 0, self.s, self.l)
        self.curpage=0

    def stage_2(self, link):

        data = self.downloader.download(link)
        if data is None:
            self.l.error("Cannot download data from %s" % link)
            return None

        tree = etree.HTML(data)

        # The following link redirects to a trampoline. Visit it.
        nlink = tree.xpath("//div[contains(@class,'Sever1')]/a")[0].attrib['href']
        # Check if the link is absolute or relative. In case it's relative, fix it.
        if not nlink.startswith('http://') and not nlink.startswith('https://'):
            # Combine it!
            nlink = urlparse.urljoin(AGGREGATOR_URL, nlink)

        data = self.downloader.download(nlink)
        if data is None:
            self.l.error("Cannot download data from %s" % nlink)
            return None

        tree = etree.HTML(data)

        # The trampoline might redirect us to an external website.
        nlink = tree.xpath("//*[@id='contentMain']/div[4]/div[1]/div[1]/div/p[1]/span/a")

        if len(nlink)==0:
            self.l.warn("Cannot find any link in page...")
            return None

        link = nlink[0].attrib['href']
        # Visit the extracted link

        # Check if the link is absolute or relative. In case it's relative, fix it.
        if not link.startswith('http://') and not link.startswith('https://'):
            # Combine it!
            link = urlparse.urljoin(AGGREGATOR_URL, link)

        # The given url will represent the download file. Note: Most of the files proposed by this aggregator
        # are external to the aggregator itself...
        headers, url = self.downloader.head(link)

        if headers is None:
            return None

        if headers['Content-Type'] == 'text/html':
            # We probably ended in a non-valid page.
            self.l.error("Invalid link: %s" % url)
            return None

        return url

    def crawl(self, session):
        # brothersoft is very simple: it only provides all the links in a single page.
        if self.curpage < 1:
            logging.info("Stage 1: Crawler starting.")

            links = []

            # Get the element list from this page
            data = self.downloader.download(MAIN_URL)
            if data is None:
                raise Exception("Cannot retrieve rankings from main_url.")

            tree = etree.HTML(data)
            r = tree.xpath(LIST_SELECTOR)

            # Now we have to visit each link and retrieve the direct link to the executable.
            for e in r:
                link = e.attrib['href']
                try:
                    if not link.startswith('http://') and not link.startswith('https://'):
                        link = urlparse.urljoin(AGGREGATOR_URL, link)

                    direct_link = self.stage_2(link)

                    if direct_link is None:
                        continue

                    # Check if the link is absolute or relative. In case it's relative, fix it.
                    if not direct_link.startswith('http://') and not direct_link.startswith('https://'):
                        # Combine it!
                        direct_link = urlparse.urljoin(AGGREGATOR_URL, direct_link)

                    if direct_link is not None:
                        self.l.debug("Found link %s." % direct_link)
                        links.append(direct_link)
                except Exception as e:
                        self.l.exception("Error while crawling %s. Ignoring..." % link)

            self.curpage+=1
            self.l.info("Crawling ended, collected %d links." % len(links))
            return links
        else:
            logging.info("Stage 1: No more links to visit.")
            # We already cralwed all the links available
            return None

if __name__ == "__main__":
    limit, outputdir = Crawler.parse_args(sys.argv[1:],AGGREGATOR_NAME)
    c = SoftpediaCrawler(download_dir=outputdir, limit=limit)
    c.start()