import scrapy

from scrapy.http import Request, FormRequest
from lxmlhtml import CustomLxmlLinkExtractor as LinkExtractor
from scrapy.conf import settings

from crawling.items import RawResponseItem
from redis_spider import RedisSpider

from scrapy_splash import SplashRequest
from scrapy_splash import SplashResponse, SplashTextResponse

from loginform import fill_login_form
from crawling.splash_util import make_splash_meta

class LinkSpider(RedisSpider):
    '''
    A spider that walks all links from the requested URL. This is
    the entrypoint for generic crawling.
    '''
    name = "link"

    def __init__(self, *args, **kwargs):
        super(LinkSpider, self).__init__(*args, **kwargs)

    def parse(self, response):
        self._logger.debug("crawled url {}".format(response.request.url))
        self._increment_status_code_stat(response)

        if 'curdepth' in response.meta:
            cur_depth = response.meta['curdepth']

        # capture raw response
        item = RawResponseItem()
        # populated from response.meta
        item['appid'] = response.meta['appid']
        item['crawlid'] = response.meta['crawlid']
        item['attrs'] = response.meta['attrs']

        # populated from raw HTTP response
        item["url"] = response.request.url
        item["response_url"] = response.url
        item["status_code"] = response.status
        item["status_msg"] = "OK"
        item["response_headers"] = self.reconstruct_headers(response)
        item["request_headers"] = response.request.headers
        item["body"] = response.body
        item["links"] = []
        if isinstance(response, (SplashResponse, SplashTextResponse)):
            if "png" in response.data:
                print " @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ "
                print " @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ "
                print " @@@@@@@@@@@@@@@@@@@@ image @@@@@@@@@@@@@@@@@@@@@@ "
                print " @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ "
                print " @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ "
                item["image"] = response.data['png']

        # login
#        if response.url == 'http://fyqe73pativ7vdif.onion/login/':
#        if response.url == 'http://mt3plrzdiyqf6jim.onion/renewal/login.php':
        if response.url in response.meta['login'] and response.status == 200:
            _id = response.meta['login'][response.url]['loginid']
            _pass = response.meta['login'][response.url]['password']

#            print response.body

#            data, url, method = fill_login_form(response.url, response.body, 'w-_-w', '1234567890')
#            data, url, method = fill_login_form(response.url, response.body, '0x0', '1234567890')
            data, url, method = fill_login_form(response.url, response.body, _id, _pass)
            yield FormRequest(url, formdata=dict(data),
                method=method, callback=self.parse, meta=make_splash_meta(response.meta))
        else:
            cur_depth = 0
            # determine whether to continue spidering
            if response.meta['maxdepth'] != -1 and cur_depth >= response.meta['maxdepth']:
                self._logger.debug("Not spidering links in '{}' because" \
                    " cur_depth={} >= maxdepth={}".format(
                                                          response.url,
                                                          cur_depth,
                                                          response.meta['maxdepth']))
            else:
                # we are spidering -- yield Request for each discovered link
                link_extractor = LinkExtractor(
                                deny_domains=response.meta['denied_domains'],
                                allow_domains=response.meta['allowed_domains'],
                                allow=response.meta['allow_regex'],
                                deny=response.meta['deny_regex'],
                                deny_extensions=response.meta['deny_extensions'])

                for link in link_extractor.extract_links(response):
                    # link that was discovered
                    item["links"].append({"url": link.url, "text": link.text, })
                    req = Request(link.url, callback=self.parse, meta=make_splash_meta({}))

                    # pass along all known meta fields
                    for key in response.meta.keys():
                        if key != 'splash' and key != 'request':
                            req.meta[key] = response.meta[key]
                    if '_splash_processed' in req.meta:
                        req.meta.pop("_splash_processed")

                    req.meta['priority'] = response.meta['priority'] - 10
                    req.meta['curdepth'] = response.meta['curdepth'] + 1

                    if 'useragent' in response.meta and \
                            response.meta['useragent'] is not None:
                        req.headers['User-Agent'] = response.meta['useragent']

                    self._logger.debug("Trying to follow link '{}'".format(req.url))
                    yield req

        # raw response has been processed, yield to item pipeline
        yield item
