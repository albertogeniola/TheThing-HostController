import urllib2
import sys
from lxml import etree
import logging
from crawler import Crawler
try: from urlparse import urljoin  # Python2
except ImportError: from urllib.parse import urljoin

TO = 20  # 20 seconds timeout for IO
AGGREGATOR_NAME = "file hippo"
AGGREGATOR_URL = "http://filehippo.com"
MAIN_URL = "http://filehippo.com/popular/%d"
LIST_SELECTOR = "//div[@id='programs-list']/div[@class='program-entry']/div[@class='program-entry-header']/a"
META_REFRESH_SELECTOR = "//meta[@http-equiv='Refresh']"
downbtn_sel_alt = "//a[@class='program-header-download-link green button-link active long btn'][boolean(@href)]"
downbtn_sel = "//div[@id='program-header']/div[@class='program-header-download-link-container']/a[1]"
attr_url = "href"


class FilehippoCrawler(Crawler):
    curpage = 1

    def __init__(self, download_dir, limit):
        super(FilehippoCrawler, self).__init__(AGGREGATOR_NAME, AGGREGATOR_URL, download_dir=download_dir, limit=limit)

    def stage_2(self, link):
        resp = urllib2.urlopen(link, timeout=TO)
        if resp.getcode() != 200:
            self.l.info("Stage 2: Cannot retrieve download link from %s" % link)
            return 0

        data = resp.read()
        tree = etree.HTML(data)

        # First check: internal link
        r = tree.xpath(downbtn_sel_alt)
        if len(r) > 0:
            # this is an alternative link
            return self.stage_2(urljoin(link, r[0].attrib[attr_url]))

        # Second check: classic link
        r = tree.xpath(downbtn_sel)
        if len(r) > 0:
            return self.stage_2(r[0].attrib[attr_url])

        # Third check: meta refresh
        r = tree.xpath(META_REFRESH_SELECTOR)
        if len(r) > 0:
            # The path might be absolute or relative
            metas = r[0].attrib['content'].split(";")
            url = None
            for meta in metas:
                if meta.find("=") == -1:
                    continue

                values = meta.split("=")
                lvalue = values[0].strip()
                rvalue = values[1].strip()

                if lvalue is not None and lvalue.lower() == 'url':
                    url = rvalue
                    break

            if url is not None:
                return urljoin(link, url)
            else:
                logging.info("Stage 2: Invalid link: %s" % link)
                return None
        else:
            logging.info("Stage 2: Invalid link: %s" % link)
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
    c = FilehippoCrawler(download_dir=outputdir, limit=limit)
    c.start()