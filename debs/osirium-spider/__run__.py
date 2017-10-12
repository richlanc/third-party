# -*- coding: utf-8 -*-

import sys

map(sys.add_package, [
    'com.gargoylesoftware.htmlunit',
    'com.gargoylesoftware.htmlunit.html',
    'com.gargoylesoftware.htmlunit.util',
    'com.gargoylesoftware.htmlunit.attachment',
    'org.apache.commons.logging',
    'org.jaxen',
    'org.jaxen.dom',
    'org.jaxen.function',
    'org.apache.http.auth',
])

from osirium.spider import main

main()
