import os
import logging
import redis
try:
    import cPickle as pickle
except ImportError:
    import pickle

from time import time
from scrapy.http import Headers, Response
from scrapy.responsetypes import responsetypes
from scrapy.utils.request import request_fingerprint
from scrapy.utils.project import data_path
from scrapy.utils.httpobj import urlparse_cached
from scrapy.utils.python import to_bytes, to_unicode

logger = logging.getLogger(__name__)

class RedisCacheStorage(object):

    def __init__(self, settings):
        self.redis_conn = redis.Redis(
                                host=settings.get('REDIS_HOST'),
                                port=settings.get('REDIS_PORT'))
        self.cachedir = data_path(settings['HTTPCACHE_DIR'], createdir=True)
        self.expiration_secs = settings.getint('HTTPCACHE_EXPIRATION_SECS')
        self.persist = settings.get('SCHEDULER_PERSIST', True)

    def open_spider(self, spider):
        self.name = 'http_cache:' + spider.name + ':'

    def close_spider(self, spider):
        if not self.persist:
            del_key=self.name+"*"
            for key in self.redis_conn.keys(del_key):
                  self.redis_conn.delete(key)

    def retrieve_response(self, spider, request):
        data = self._read_data(spider, request)
        if data is None:
            return  # not cached
        url = data['url']
        status = data['status']
        headers = Headers(data['headers'])
        body = data['body']
        respcls = responsetypes.from_args(headers=headers, url=url)
        response = respcls(url=url, headers=headers, status=status, body=body)
        return response

    def store_response(self, spider, request, response):
        key = self._request_key(request)
        data = {
            'status': response.status,
            'url': response.url,
            'headers': dict(response.headers),
            'body': response.body,
        }
        with self.redis_conn.pipeline() as pipe:
            pipe.watch(self.name + key + '_data')  # ---- LOCK
            pipe.multi()
            self.redis_conn.set( 
                self.name + key + '_data', 
                pickle.dumps(data, protocol=2) )
            if 0 < self.expiration_secs:
                pipe.expire(
                    self.name + key + '_data',
                    int(self.expiration_secs))
            pipe.execute()

    def _read_data(self, spider, request):
        key = self._request_key(request)

        data = self.redis_conn.get(self.name + key + '_data')
        if data is None:
            return  # invalid entry
        else:
            return pickle.loads(data)

    def _request_key(self, request):
        return to_bytes(request_fingerprint(request))

