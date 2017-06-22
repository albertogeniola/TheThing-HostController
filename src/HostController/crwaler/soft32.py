import sys
from lxml import etree
import logging
from crawler import Crawler
from downloaders import LazyDownloader
import urlparse

AGGREGATOR_NAME = "soft32"
AGGREGATOR_URL = "http://www.soft32.com"
MAIN_URL = "http://www.soft32.com/windows/most-popular/%d/?sort=popularity"
LIST_SELECTOR = "//table[@class='list programs']/tbody/tr/td[@class='description']/div"


class SoftpediaCrawler(Crawler):
    downloader = None
    curpage = 1

    def __init__(self, download_dir, limit):
        super(SoftpediaCrawler, self).__init__(AGGREGATOR_NAME, AGGREGATOR_URL, download_dir=download_dir, limit=limit)
        self.downloader = LazyDownloader(0, 0, self.s, self.l)
        self.curpage = 1

    def stage_2(self, link):
        # Soft32 combines the download with a free-download suffix that tells to the webserver to show us download options.
        download_link = urlparse.urljoin(link,"free-download/?dm=1")
        data = self.downloader.download(download_link)
        if data is None:
            self.l.error("Cannot download data from %s" % link)
            return None

        tree = etree.HTML(data)

        r = tree.xpath("//a[@data-target='download']/@data-download")

        if len(r)==0:
            self.l.warning("Download link not found for %s" % link)
            return None
        else:
            self.l.debug("Found link %s!" % r[0])
            return r[0]

    def crawl(self, session):

        logging.info("Stage 1: Downloading from page %d." % self.curpage)

        links = []

        # Get the element list from this page
        page = MAIN_URL%self.curpage
        data = self.downloader.download(page)
        if data is None:
            raise Exception("Cannot retrieve rankings from %s." % page)

        tree = etree.HTML(data)
        r = tree.xpath("//table[@class='list programs']//tr/td[@class='description']/div")

        # Now we have to visit each link and retrieve the direct link to the executable.
        for e in r:
            try:
                link = e.xpath("a[@class='soft']")[0].attrib['href']
                lic = e.xpath("span[contains(@class,'licence')]")[0].text.strip().lower()

                # Discard non-free software
                if lic not in ('free', 'free to try'):
                    self.l.info("Software is a %s thus not free (%s)." % (lic, link))
                    continue

                direct_link = self.stage_2(link)

                if direct_link is not None:
                    links.append(direct_link)

            except Exception as e:
                    self.l.exception("Error while crawling... Skipping.")

        self.l.info("Crawling page %d finished, collected %d links." % (self.curpage, len(links)))
        self.curpage+=1
        return links


if __name__ == "__main__":
    limit, outputdir = Crawler.parse_args(sys.argv[1:],AGGREGATOR_NAME)
    c = SoftpediaCrawler(download_dir=outputdir, limit=limit)
    c.start()