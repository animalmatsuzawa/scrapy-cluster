import os
import six
import logging
from collections import defaultdict

from scrapy.exceptions import NotConfigured
from scrapy.http import Response
from scrapy.http.cookies import CookieJar
from scrapy.utils.python import to_native_str

from scrapy import signals
from scrapy.downloadermiddlewares.cookies import CookiesMiddleware

import redis
try:
    import cPickle as pickle
except ImportError:
    import pickle


from scrapy_splash import SplashCookiesMiddleware
from scrapy_splash.responsetypes import responsetypes
from scrapy_splash.cookies import jar_to_har, har_to_jar
from scrapy_splash.utils import (
    scrapy_headers_to_unicode_dict,
    json_based_hash,
    parse_x_splash_saved_arguments_header,
)

logger = logging.getLogger(__name__)


class RedisCookiesMiddleware(CookiesMiddleware):
    """This middleware enables working with sites that need cookies"""

    def __init__(self, crawler):
        self.redis_conn = redis.Redis(
                                host=crawler.settings.get('REDIS_HOST'),
                                port=crawler.settings.get('REDIS_PORT'))
        self.persist = crawler.settings.get('SCHEDULER_PERSIST', True)
        self.redis_key = 'cookiejar'
        _jars = self.redis_conn.get(self.redis_key)  
        if _jars is None:
            self.jars = defaultdict(CookieJar)
            self.redis_conn.set(self.redis_key, pickle.dumps(self.jars, protocol=-1))
        else:
            self.jars = pickle.loads(_jars)
        self.debug = crawler.settings.getbool('COOKIES_DEBUG')

    @classmethod
    def from_crawler(cls, crawler):
        if not crawler.settings.getbool('COOKIES_ENABLED'):
            raise NotConfigured
        _this = cls(crawler)
        crawler.signals.connect(_this.spider_closed, signal=signals.spider_closed)
        return _this

    def spider_closed(self, spider):
        if not self.persist:
            self.redis_conn.delete( self.redis_key )

    def process_request(self, request, spider):
        if request.meta.get('dont_merge_cookies', False):
            return

        cookiejarkey = request.meta.get("cookiejar")

        _jars = self.redis_conn.get(self.redis_key)
        if _jars is None:
            self.jars = defaultdict(CookieJar)
            self.redis_conn.set(self.redis_key, pickle.dumps(self.jars, protocol=-1))
        else:
            self.jars = pickle.loads(_jars)
#        self.jars = pickle.loads(_jars)

        jar = self.jars[cookiejarkey]
        cookies = self._get_request_cookies(jar, request)
        for cookie in cookies:
            jar.set_cookie_if_ok(cookie, request)

        # set Cookie header
        request.headers.pop('Cookie', None)
        jar.add_cookie_header(request)
        self._debug_cookie(request, spider)

        self.redis_conn.set(self.redis_key, pickle.dumps(self.jars, protocol=-1))

    def process_response(self, request, response, spider):
        if request.meta.get('dont_merge_cookies', False):
            return response

        # extract cookies from Set-Cookie and drop invalid/expired cookies
        cookiejarkey = request.meta.get("cookiejar")

        _jars = self.redis_conn.get(self.redis_key)
        if _jars is None:
            self.jars = defaultdict(CookieJar)
            self.redis_conn.set(self.redis_key, pickle.dumps(self.jars, protocol=-1))
        else:
            self.jars = pickle.loads(_jars)
#        self.jars = pickle.loads(_jars)

        jar = self.jars[cookiejarkey]
        jar.extract_cookies(response, request)
        self._debug_set_cookie(response, spider)

        self.redis_conn.set(self.redis_key, pickle.dumps(self.jars, protocol=-1))
        return response

    def _debug_cookie(self, request, spider):
        if self.debug:
            cl = [to_native_str(c, errors='replace')
                  for c in request.headers.getlist('Cookie')]
            if cl:
                cookies = "\n".join("Cookie: {}\n".format(c) for c in cl)
                msg = "Sending cookies to: {}\n{}".format(request, cookies)
                logger.debug(msg, extra={'spider': spider})

    def _debug_set_cookie(self, response, spider):
        if self.debug:
            cl = [to_native_str(c, errors='replace')
                  for c in response.headers.getlist('Set-Cookie')]
            if cl:
                cookies = "\n".join("Set-Cookie: {}\n".format(c) for c in cl)
                msg = "Received cookies from: {}\n{}".format(response, cookies)
                logger.debug(msg, extra={'spider': spider})

    def _format_cookie(self, cookie):
        # build cookie string
        cookie_str = '%s=%s' % (cookie['name'], cookie['value'])

        if cookie.get('path', None):
            cookie_str += '; Path=%s' % cookie['path']
        if cookie.get('domain', None):
            cookie_str += '; Domain=%s' % cookie['domain']

        return cookie_str

    def _get_request_cookies(self, jar, request):
        if isinstance(request.cookies, dict):
            cookie_list = [{'name': k, 'value': v} for k, v in \
                    six.iteritems(request.cookies)]
        else:
            cookie_list = request.cookies

        cookies = [self._format_cookie(x) for x in cookie_list]
        headers = {'Set-Cookie': cookies}
        response = Response(request.url, headers=headers)

        return jar.make_cookies(response, request)


class SplashRedisCookiesMiddleware(SplashCookiesMiddleware):
    """
    This middleware maintains cookiejars for Splash requests.
    It gets cookies from 'cookies' field in Splash JSON responses
    and sends current cookies in 'cookies' JSON POST argument.
    It should process requests before SplashMiddleware, and process responses
    after SplashMiddleware.
    """
    def __init__(self, crawler):
        self.redis_conn = redis.Redis(
                                host=crawler.settings.get('REDIS_HOST'),
                                port=crawler.settings.get('REDIS_PORT'))
        self.persist = crawler.settings.get('SCHEDULER_PERSIST', True)
        self.redis_key = 'splash:cookiejar'
        _jars = self.redis_conn.get(self.redis_key)
        if _jars is None:
            self.jars = defaultdict(CookieJar)
            self.redis_conn.set(self.redis_key, pickle.dumps(self.jars, protocol=-1))
        else:
            self.jars = pickle.loads(_jars)
        self.debug = crawler.settings.getbool('SPLASH_COOKIES_DEBUG')

    @classmethod
    def from_crawler(cls, crawler):
        _this = cls(crawler)
        crawler.signals.connect(_this.spider_closed, signal=signals.spider_closed)
        return _this

    def spider_closed(self, spider):
        if not self.persist:
            self.redis_conn.delete( self.redis_key )

    def process_request(self, request, spider):
        """
        For Splash requests add 'cookies' key with current
        cookies to request.meta['splash']['args']
        """
        if 'splash' not in request.meta:
            return

        if request.meta.get('_splash_processed'):
            return

        splash_options = request.meta['splash']

        splash_args = splash_options.setdefault('args', {})
        if 'cookies' in splash_args:  # cookies already set
            return

        if 'session_id' not in splash_options:
            return

        _jars = self.redis_conn.get(self.redis_key)
        if _jars is None:
            self.jars = defaultdict(CookieJar)
            self.redis_conn.set(self.redis_key, pickle.dumps(self.jars, protocol=-1))
        else:
            self.jars = pickle.loads(_jars)

        jar = self.jars[splash_options['session_id']]

        cookies = self._get_request_cookies(request)
        har_to_jar(jar, cookies)

        splash_args['cookies'] = jar_to_har(jar)
        self._debug_cookie(request, spider)

    def process_response(self, request, response, spider):
        """
        For Splash JSON responses add all cookies from
        'cookies' in a response to the cookiejar.
        """
        from scrapy_splash import SplashJsonResponse
        if not isinstance(response, SplashJsonResponse):
            return response

        if 'cookies' not in response.data:
            return response

        if 'splash' not in request.meta:
            return response

        if not request.meta.get('_splash_processed'):
            warnings.warn("SplashCookiesMiddleware requires SplashMiddleware")
            return response

        splash_options = request.meta['splash']
        session_id = splash_options.get('new_session_id',
                                        splash_options.get('session_id'))
        if session_id is None:
            return response

        _jars = self.redis_conn.get(self.redis_key)
        if _jars is None:
            self.jars = defaultdict(CookieJar)
            self.redis_conn.set(self.redis_key, pickle.dumps(self.jars, protocol=-1))
        else:
            self.jars = pickle.loads(_jars)

        jar = self.jars[session_id]
        request_cookies = splash_options['args'].get('cookies', [])
        har_to_jar(jar, response.data['cookies'], request_cookies)
        self._debug_set_cookie(response, spider)
        response.cookiejar = jar

        self.redis_conn.set(self.redis_key, pickle.dumps(self.jars, protocol=-1))

        return response
