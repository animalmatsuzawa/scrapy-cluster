# -*- coding: utf-8 -*-

from scrapy.conf import settings

def make_splash_meta( _meta ):
    script = """
    function main(splash)
      splash:init_cookies(splash.args.cookies)
      assert(splash:go{
          splash.args.url,
          headers=splash.args.headers,
          http_method=splash.args.http_method,
          body=splash.args.body,
        })
      assert(splash:wait(0.5))

      local entries = splash:history()
      local last_response = entries[#entries].response
      return {
        url = splash:url(),
        headers = last_response.headers,
        http_status = last_response.status,
        cookies = splash:get_cookies(),
        html = splash:html(),
        png = splash:png{render_all=true},
      }
    end
    """
    _meta['splash']={ 
            'args': {
                'lua_source': script,
            },
            'endpoint': 'execute',
            'session_id': 1,
        }
    proxy = settings.get('SPLASH_PROXY_URL')
    if proxy is not None:
        _meta['splash']['args']['proxy']=proxy
    
    if '_splash_processed' in _meta:
        _meta.pop('_splash_processed')
    return _meta
