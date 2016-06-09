#!/usr/bin/python

from kafka.client import KafkaClient
from kafka.consumer import SimpleConsumer
from kafka.producer import SimpleProducer
from kafka.common import OffsetOutOfRangeError
from collections import OrderedDict
from kafka.common import KafkaUnavailableError

import time
import json
import sys
import argparse
import redis

from redis.exceptions import ConnectionError

from jsonschema import ValidationError
from jsonschema import Draft4Validator, validators

import sys,os
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + '/../utils')
from scutils.log_factory import LogFactory
from scutils.settings_wrapper import SettingsWrapper
from scutils.method_timer import MethodTimer
from scutils.stats_collector import StatsCollector
from scutils.argparse_helper import ArgparseHelper

try:
    import cPickle as pickle
except ImportError:
    import pickle

import os
from plugins.scraper_handler import ScraperHandler

class Feed:

    def __init__(self, settings_name, unit_test=False):
        '''
        @param settings_name: the local settings file name
        @param unit_test: whether running unit tests or not
        '''
        self.settings_name = settings_name
        self.wrapper = SettingsWrapper()
        self.logger = None
        self.unit_test = unit_test

    def setup(self, level=None, log_file=None, json=None):
        '''
        Load everything up. Note that any arg here will override both
        default and custom settings

        @param level: the log level
        @param log_file: boolean t/f whether to log to a file, else stdout
        @param json: boolean t/f whether to write the logs in json
        '''
        self.settings = self.wrapper.load(self.settings_name)

        my_level = level if level else self.settings['LOG_LEVEL']
        # negate because logger wants True for std out
        my_output = not log_file if log_file else self.settings['LOG_STDOUT']
        my_json = json if json else self.settings['LOG_JSON']
        self.logger = LogFactory.get_instance(json=my_json, stdout=my_output,
                                              level=my_level,
                                              name=self.settings['LOGGER_NAME'],
                                              dir=self.settings['LOG_DIR'],
                                              file=self.settings['LOG_FILE'],
                                              bytes=self.settings['LOG_MAX_BYTES'],
                                              backups=self.settings['LOG_BACKUPS'])

        self.validator = self.extend_with_default(Draft4Validator)

    def extend_with_default(self, validator_class):
        '''
        Method to add default fields to our schema validation
        ( From the docs )
        '''
        validate_properties = validator_class.VALIDATORS["properties"]

        def set_defaults(validator, properties, instance, schema):
            for error in validate_properties(
                validator, properties, instance, schema,
            ):
                yield error

            for property, subschema in properties.iteritems():
                if "default" in subschema:
                    instance.setdefault(property, subschema["default"])

        return validators.extend(
            validator_class, {"properties": set_defaults},
        )


    def feed(self, json_item):
        instance = ScraperHandler()
        instance._set_logger(self.logger)
        instance.setup(self.settings)
        the_schema = None
        with open(self.settings['PLUGIN_DIR'] + instance.schema) as the_file:
            the_schema = json.load(the_file)

        the_dict = json_item
        ret = True
        try:
            self.validator(the_schema).validate(the_dict)
            instance.handle(the_dict)
            self.logger.info("Successfully fed item to Kafka")
        except ValidationError:
            self.logger.error("Failed to feed item into Kafka")

def main():
    # initial parsing setup
    parser = argparse.ArgumentParser(
        description='Kafka Monitor: Monitors and validates incoming Kafka ' \
            'topic cluster requests\n', add_help=False)
    parser.add_argument('-h', '--help', action=ArgparseHelper,
                        help='show this help message and exit')

    #base_parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-s', '--settings', action='store',
                             required=False,
                             help="The settings file to read from",
                             default="localsettings.py")
    parser.add_argument('-ll', '--log-level', action='store',
                             required=False, help="The log level",
                             default=None,
                             choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'])
    parser.add_argument('-lf', '--log-file', action='store_const',
                        required=False, const=True, default=None,
                        help='Log the output to the file specified in '
                        'settings.py. Otherwise logs to stdout')
    parser.add_argument('-lj', '--log-json', action='store_const',
                        required=False, const=True, default=None,
                        help="Log the data in JSON format")

    json_parser = parser.add_argument('json', help='The JSON object as a string')

    args = vars(parser.parse_args())

    feed = Feed(args['settings'])
    feed.setup(level=args['log_level'], log_file=args['log_file'],
                        json=args['log_json'])

    json_req = args['json']
    try:
        parsed = json.loads(json_req)
    except ValueError:
        feed.logger.info("JSON failed to parse")
        return 1
    else:
        return feed.feed(parsed)


if __name__ == "__main__":
    sys.exit(main())
