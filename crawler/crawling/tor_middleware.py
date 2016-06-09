# -*- coding: utf-8 -*-

import os
import random
import scrapy
import time
from scrapy.downloadermiddlewares.retry import RetryMiddleware

#from scrapy.conf import settings

class RandomUserAgentMiddleware(object):
    def process_request(self, request, spider):
        ua  = random.choice(scrapy.conf.settings.get('USER_AGENT_LIST'))
#        print 'RandomUserAgentMiddleware:' + ua
        if ua:
            request.headers.setdefault('User-Agent', ua)

class ProxyMiddleware(object):
    def process_request(self, request, spider):
#        print 'ProxyMiddleware:' + scrapy.conf.settings.get('HTTP_PROXY')
        request.meta['proxy'] = scrapy.conf.settings.get('HTTP_PROXY')

class RetryChangeProxyMiddleware(RetryMiddleware):
    retry=''
    def __init__(self, settings):
        super(RetryChangeProxyMiddleware, self).__init__(settings)

    def _retry(self, request, reason, spider):
        print( 'start RetryChangeProxyMiddleware:')
        os.system('/usr/local/bin/nym.sh')
        time.sleep(3)
#        print 'ret RetryChangeProxyMiddleware:'
        return RetryMiddleware._retry(self, request, reason, spider)

