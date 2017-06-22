import sys, getopt
from lxml import etree
import logging
from crawler import Crawler
from downloaders import LazyDownloader

AGGREGATOR_NAME = "softpedia"
AGGREGATOR_URL = "http://en.softpedia.com/"
MAIN_URL = "http://win.softpedia.com/index%s.free.shtml"
LIST_SELECTOR = "//div[@id='sjmp']/div[contains(@class, 'grid_48') and contains(@class, 'dlcls')]"


class SoftpediaCrawler(Crawler):
    downloader = None

    def __init__(self, download_dir, limit):
        super(SoftpediaCrawler, self).__init__(AGGREGATOR_NAME, AGGREGATOR_URL, download_dir=download_dir, limit=limit)
        self.downloader = LazyDownloader(0.5, 2, session=self.s, logger=self.l)

    def stage_2(self, link):

        data = self.downloader.download(link)
        if data is None:
            self.l.error("Cannot download data from %s" % link)
            return None

        tree = etree.HTML(data)

        # Softpedia uses ajax service to get the download link list given the download id.
        # Let's use some blackmagic to retrieve the id
        download_id = filter(lambda x:x.find("var spjs_prog_id=")!=-1, data.split('\n'))[0].split("=")[1].split(';')[0]
        relative_ajax = "http://www.softpedia.com/_xaja/dlinfo.php?t=15&id=%s" % download_id

        # Now we need to query the ajax service and get link info
        data = self.downloader.download(relative_ajax)
        if data is None:
            self.l.error("Cannot download data from %s" % relative_ajax)
            return None

        tree = etree.HTML(data)
        r = tree.xpath("//div[@class='dllinkbox2']/a")

        # Now visit the last page and retrieve the manual link
        if len(r) == 0:
            return None

        link = r[0].attrib['href']
        data = self.downloader.download(link)
        if data is None:
            self.l.error("Cannot download data from %s" % link)
            return None

        tree = etree.HTML(data)
        direct_link = tree.xpath("//div[@id='manstart']/a")[0].attrib['href']
        return direct_link

    def crawl(self, session):

        maxpages = 30
        # Softpedia does not provide rankings for top downloads. However, we might rely on download counters,
        # providing results in order of popularity. So, we first scan all the pages and then we build the list.
        logging.info("Stage 1: Crawler starting. We will scan all pages first, then provide results sorted by downloads.")

        links = []
        for curpage in range(1, 31):
            self.l.info("Stage 1: Collecting links from page %d of %d" % (curpage, maxpages))

            # Get the element list from this page
            link = MAIN_URL % str(curpage) if curpage > 1 else MAIN_URL % ""
            resp = self.downloader.download(link)
            if resp is None:
                raise Exception("Could not retrieve links from %s" % link)

            tree = etree.HTML(resp)
            r = tree.xpath(LIST_SELECTOR)

            # For each element in the list filter by windows 7 32 bit compatibility, and get the popularity based on
            # downloads
            for l in r:
                # Check compatibility with Windows 7
                oses = [a.lower().strip() for a in l.xpath(".//div[@class='os']")[0].text.split('/')]
                downloads = int(l.xpath(".//div[@class='info fr']/ul/li[2]")[0].text.split('download')[0].replace(',',''))
                link = l.xpath(".//h4[@class='ln']/a")[0].attrib['href']

                # Only go ahead if we are compatible with windows 7
                if 'windows all' in oses or 'windows 7' in oses:
                    try:
                        # Now inspect the second page and retrieve the direct link to the binary
                        direct_link = self.stage_2(link)

                        # At this point we have everything, so store info in the list.
                        if direct_link is not None:
                            obj = dict()
                            obj['downloads'] = downloads
                            obj['link'] = direct_link
                            links.append(obj)
                            self.l.debug("Collected downloads: %s link: %s" % (downloads, direct_link))
                    except Exception as e:
                        self.l.exception("Stage 1: [Failed] <%s>" % link)

        # We now return the list of download links we want to download
        return [s['link'] for s in sorted(links, key=lambda obj: obj['downloads'])]

if __name__ == "__main__":
    limit, outputdir = Crawler.parse_args(sys.argv[1:],AGGREGATOR_NAME)
    c = SoftpediaCrawler(download_dir=outputdir, limit=limit)
    c.start()