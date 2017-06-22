import sys
from lxml import etree
import logging
from crawler import Crawler
from downloaders import LazyDownloader
import urlparse

AGGREGATOR_NAME = "informer"
AGGREGATOR_URL = "http://software.informer.com"
MAIN_URL = "http://software.informer.com/software/%s"
LIST_SELECTOR = "//div[@class='set_program_block']"
ADDITIONAL_HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.143 Safari/537.36'}


class SoftwareInformerCrawler(Crawler):
    downloader = None
    curpage = 1

    def __init__(self, download_dir, limit):
        super(SoftwareInformerCrawler, self).__init__(AGGREGATOR_NAME, AGGREGATOR_URL, download_dir=download_dir, limit=limit, additional_headers=ADDITIONAL_HEADERS)
        self.downloader = LazyDownloader(1, 2, self.s, self.l, ADDITIONAL_HEADERS)
        self.curpage = 1

    def _handle_element_ajax(self, element):
        # Extract the ajax call and perform it here.
        oclick = element.attrib['onclick']
        lnk = oclick.split("return show_download_content('")[1].split("',")[0]
        data = self.downloader.download(lnk)
        tree = etree.HTML(data)
        r = tree.xpath("//div[@class='download-direct']/i/a")[0]
        return r.attrib['href']

    def stage_2(self, link):
        # softwareinformer combines the download with a download suffix that tells to the webserver to show us download options.
        download_link = urlparse.urljoin(link, "download")
        data = self.downloader.download(download_link)
        if data is None:
            self.l.error("Cannot download data from %s" % link)
            return None

        tree = etree.HTML(data)

        r = tree.xpath("//div[@class='otherver']/p[@class='dtb_v2']")

        if len(r) == 0:
            self.l.warning("Download link not found for %s" % link)
            return None
        else:
            # Select the first proposed download
            link = r[0].xpath("a[contains(@class,'otherver-download')]")[0].attrib['href']

            # This downloader may provide ajax downloading. If this is the case, handle it here.
            if link == '#':
                link = self._handle_element_ajax(r[0].xpath("a[contains(@class,'otherver-download')]")[0])

            # In case we have options, choose the one presenting 32bits, if exists
            if len(r) > 1:
                for e in r:
                    bits = e.xpath("span[@class='otherver-ver']/span[@class='otherver-bit']")
                    if len(bits) > 0:
                        bits = bits[0].text
                        if bits is not None and bits.find('32') != -1:
                            # This is a good download. Use it!
                            link = e.xpath("a[@class='otherver-download']")[0].attrib['href']
                            if link == '#':
                                link = self._handle_element_ajax(e.xpath("a[@class='otherver-download']")[0])
                            break

            self.l.debug("Found link %s!" % link)
            return link

    def crawl(self, session):

        logging.info("Stage 1: Downloading from page %d." % self.curpage)

        links = []

        # Get the element list from this page
        page = MAIN_URL % self.curpage
        data = self.downloader.download(page)
        if data is None:
            raise Exception("Cannot retrieve rankings from %s." % page)

        tree = etree.HTML(data)
        r = tree.xpath(LIST_SELECTOR)

        # Now we have to visit each link and retrieve the direct link to the executable.
        for e in r:
            try:
                link = e.xpath("div/a[@class='set_prog_h']")[0].attrib['href']

                licence = e.xpath("div/div[@class='set_pr_infoline']/span[@class='set_pr_lictype']")
                if len(licence)>0:
                    licence = licence[0].text.lower().strip()
                else:
                    self.l.warning("Software %s has unknown licence type..." % link)
                    licence = 'unknown'

                # Discard non-free software, but accept unknown licences.
                if licence not in ('freeware', 'open source', 'unknown'):
                    self.l.info("Software is a %s thus not free (%s)." % (licence, link))
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
    c = SoftwareInformerCrawler(download_dir=outputdir, limit=limit)
    c.start()