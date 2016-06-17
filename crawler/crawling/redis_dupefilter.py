import redis
import time
from scrapy.dupefilters import BaseDupeFilter
from scrapy.utils.request import request_fingerprint
from scrapy_splash.dupefilter import splash_request_fingerprint

class RFPDupeFilter(BaseDupeFilter):
    '''
    Redis-based request duplication filter
    '''

    def __init__(self, server, key, timeout):
        '''
        Initialize duplication filter

        @param server: the redis connection
        @param key: the key to store the fingerprints
        @param timeout: number of seconds a given key will remain once idle
        '''
        self.server = server
        self.key = key
        self.timeout = timeout

    @classmethod
    def from_settings(cls, settings):
        server = redis.Redis(host=settings.get('REDIS_HOST'),
                             port=settings.get('REDIS_PORT'))
        timeout = settings.get('DUPEFILTER_TIMEOUT', 600)

        #key = "dupefilter:%s" % int(time.time())
        key = "dupefilter:"
        return cls(server, key, timeout)

    def set_key( self, _key ):
        self.key = _key

    def request_seen(self, request):
        fp = self.request_fingerprint(request)
        c_id = request.meta['crawlid']

        added = self.server.sadd(self.key + ":" + c_id, fp)
        if self.timeout != -1:
            self.server.expire(self.key + ":" + c_id, self.timeout)

        return not added

    def close(self, reason):
        '''
        Delete data on close. Called by scrapy's scheduler
        '''
        self.clear()

    def clear(self):
        '''
        Clears fingerprints data
        '''
        #self.server.delete(self.key)
        del_key=self.key+":*"
        for key in self.server.keys(del_key):
          self.server.delete(key)

    def request_fingerprint(self, request):
        return request_fingerprint(request)

class SplashRFPDupeFilter(RFPDupeFilter):
    def request_fingerprint(self, request):
        return splash_request_fingerprint(request)
