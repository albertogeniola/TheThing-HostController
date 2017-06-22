import urllib2
import sys
from lxml import etree
import logging
from crawler import Crawler

TO = 20  # 20 seconds timeout for IO
AGGREGATOR_NAME = "softonic"
AGGREGATOR_URL = "http://en.softonic.com/"
MAIN_URL = "http://en.softonic.com/s/full-version-free-software/windows-7/%s"
LIST_SELECTOR = "//li[@class='js-organic-result']/article[@class='cu-app-list']/a"
downbtn_sel = "//a[@class='button-main-download-xl']"
downbtn_last = "//a[(@class='button-main-download-s' or @class='button-main-download-xl') and @id!='windows-store-link']"
attr_url = "href"


class SoftonicCrawler(Crawler):
    curpage = 1

    def __init__(self, download_dir, limit):
        super(SoftonicCrawler, self).__init__(AGGREGATOR_NAME, AGGREGATOR_URL, download_dir=download_dir, limit=limit)

    def stage_2(self, link, rec=0):
        if rec>1:
            return link

        resp = urllib2.urlopen(link, timeout=TO)
        if resp.getcode() != 200:
            self.l.info("Stage 2: Cannot retrieve download link from %s" % link)
            return 0

        data = resp.read()

        tree = etree.HTML(data)

        r = tree.xpath(downbtn_sel)
        if len(r) > 0:
            recursion = rec+1
            return self.stage_2(r[0].attrib[attr_url], recursion)
        else:
            return None

    def crawl(self, session):
        logging.info("Stage 1: Crawler starting...")

        self.l.info("Stage 1: Collecting links from page %d" % self.curpage)

        # Get the element list from this page
        link = MAIN_URL % self.curpage
        resp = urllib2.urlopen(link, timeout=TO)
        if resp.getcode() != 200:
            resp.close()
            raise Exception("Could not retrieve links from %s" % link)

        data = resp.read()
        tree = etree.HTML(data)
        r = tree.xpath(LIST_SELECTOR)

        # Now parse all the elements in the list
        links = []
        for l in r:
            try:
                link = self.stage_2(l.attrib['href'])
                if link is not None:
                    links.append(link)
            except Exception as e:
                self.l.exception("Stage 1: [Failed] <%s>" % l.attrib['href'])
                continue

        # Increment the counter for future queries
        self.curpage += 1
        return links

if __name__ == "__main__":
    limit, outputdir = Crawler.parse_args(sys.argv[1:],AGGREGATOR_NAME)
    c = SoftonicCrawler(download_dir=outputdir, limit=limit)
    c.start()