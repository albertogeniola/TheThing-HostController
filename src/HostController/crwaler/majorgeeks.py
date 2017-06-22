import sys
from lxml import etree
import logging
from crawler import Crawler
from downloaders import LazyDownloader
import urlparse

AGGREGATOR_NAME = "majorgeeks"
AGGREGATOR_URL = "http://www.majorgeeks.com"
MAIN_URL = "http://www.majorgeeks.com/mg/topdownloads/last_week.html"
LIST_SELECTOR = "//div[@class='geekytitle']/a"


class SoftpediaCrawler(Crawler):
    downloader = None

    def __init__(self, download_dir, limit):
        super(SoftpediaCrawler, self).__init__(AGGREGATOR_NAME, AGGREGATOR_URL, download_dir=download_dir, limit=limit)
        self.downloader = LazyDownloader(0, 0, self.s, self.l)

    def stage_2(self, link):

        data = self.downloader.download(link)
        if data is None:
            self.l.error("Cannot download data from %s" % link)
            return None

        tree = etree.HTML(data)

        # Here we have many interesting information that we might use to filter inputs.
        # For instance we might check compatibility with windows 7.
        r = str(tree.xpath("//*[@id='nointelliTXT']//strong[text()='Requires:']/following-sibling::node()")[0]).strip()
        if not (r.startswith("Win") and '7' in [x.strip() for x in r.split('/')] or r.find('Win 7')!=-1 or r.find('Win7')!=-1 or r.find('Windows 7')!=-1 or r.find('Windows7')!=-1 or r.find('Win All')!=-1):
            self.l.warning("Link %s is not compatible with Windows 7. Skipping.", link)
            return None

        # Prefer MajorGeeks links, otherwise check for author's site
        r = tree.xpath("//*[@id='nointelliTXT']//strong[contains(text(), 'Download@MajorGeeks')]/..")
        if len(r)==0:
            r = tree.xpath("//*[@id='nointelliTXT']//strong[contains(text(), 'Download@Authors Site')]/..")

        if len(r)==0:
            self.l.warning("Download link not found for %s" % link)
            return None

        # At this point extract the link for the last page
        nlink = r[0].attrib['href']

        # Check if the link is absolute or relative. In case it's relative, fix it.
        if not nlink.startswith('http://') and not nlink.startswith('https://'):
            # Combine it!
            nlink = urlparse.urljoin(AGGREGATOR_URL, nlink)

        # Once we got the link to the last page, we need to visit it. This will cause the webserver so set a session
        # variable storing our file we want to download. At that point, we just have to visit a partiular URL
        # that will redirect us to the correct final URL (302). This is a curious way of handling downloads...
        data = self.downloader.download(nlink)
        if data is None:
            self.l.debug("Cannot retrieve page %s" % nlink)
            return None

        # Now visit the very last url and expect a 302 with the correct download link
        direct_link = self.downloader.get_redirect_link("http://www.majorgeeks.com/index.php?ct=files&action=download&")

        if direct_link is None:
            self.l.debug("Cannot retrieve redirected link for %s" % nlink)
            return None
        else:
            return direct_link

    def crawl(self, session):
        self.curpage = 0
        # majorGeeks is very simple: it only provides all the links in a single page.
        if self.curpage < 1:
            logging.info("Stage 1: Crawler starting. Retrieving top download rankings first.")

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