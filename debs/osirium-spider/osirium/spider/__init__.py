# -*- coding: utf-8 -*-

"""
general purpose Jython web crawler operated by templates
"""

import time

timestamp = int(time.time())

import logging
import logging.config
import logging.handlers

logger = logging.getLogger('spider')
logger.setLevel(logging.INFO)

def main():
    import sys
    import subprocess
    import codecs
    import optparse

    from osirium.spider import handler

    parser = optparse.OptionParser()
    parser.add_option('-l', '--logfile', action='store', type='string', dest='logfile', default='spider.log', help='target directory for log output')
    parser.add_option('--cache', action='store_true', dest='cache', help='load Java libraries and then exit')
    parser.add_option('--validate', action='store_true', dest='validate', help='validate template file but do not begin crawling')
    (options, args) = parser.parse_args()

    from org.apache.commons.logging import LogFactory
    LogFactory.getFactory().setAttribute("org.apache.commons.logging.Log", "org.apache.commons.logging.impl.NoOpLog")

    if options.cache:
        sys.exit()

    if options.logfile == '-':
        loghandler = logging.StreamHandler()
    else:
        loghandler = logging.FileHandler(options.logfile)

    loghandler.setFormatter(logging.Formatter('%(asctime)s,%(msecs)03d %(levelname)-5.5s [%(name)s] %(message)s', '%H:%M:%S'))
    logger.addHandler(loghandler)

    template = sys.stdin.read()

    if options.validate:
        process = subprocess.Popen('xmllint --valid -', shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate(template)
        if process.returncode > 0:
            print >> sys.stderr, template
            print >> sys.stderr, '======= [TEMPLATE ERROR] ======='
            print >> sys.stderr, stderr
    else:
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout)
        sys.stdout.write(handler.Spider.parse(template))
        sys.stdout.flush()

if __name__ == "__main__":
    main()
