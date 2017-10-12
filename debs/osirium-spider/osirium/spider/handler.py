from __future__ import with_statement, absolute_import

import re
import string
import os
import time
import errno

from . import ssl_utilities


from com.gargoylesoftware import htmlunit
from org.apache.http import auth

import java.util
import java.net
import java.io
import java.nio.channels
import tempfile

from xml.etree import ElementTree

import org.jaxen
import org.jaxen.dom
import org.jaxen.function

from . import logger

import jarray

from java.util.logging import LogManager


ESCAPE = re.compile(r'[\x00-\x1f\\"\b\f\n\r\t]')
SUBSTITUTIONS = {
    '\\': '\\\\',
    '"': '\\"',
    '\b': '\\b',
    '\f': '\\f',
    '\n': '\\n',
    '\r': '\\r',
    '\t': '\\t',
}


def coerce_quote(s):
    def replace(match):
        return SUBSTITUTIONS[match.group(0)]
    return u'"' + ESCAPE.sub(replace, unicode(s)) + u'"'


def coerce_to_bool(value):
    value = str(value)
    if re.match('^(true)$', value, re.IGNORECASE):
        return True
    elif re.match('^(false)$', value, re.IGNORECASE):
        return False
    raise ValueError('unable to coerce %r into a boolean', value)


def from_pattern(pattern, type, *args):
    def coerce(value):
        value = str(value)
        match = pattern.search(value)
        if match is not None:
            return type(match.group(1), *args)
        raise ValueError('unable to coerce %r into a %s' % (value, type.__name__))
    return coerce

coerce_to_int = from_pattern(re.compile('([-+]?[0-9]+)', re.IGNORECASE), int)


def red(o):
    return u'\033[91m%s\033[0m' % o


def blue(o):
    return u'\033[94m%s\033[0m' % o


def green(o):
    return u'\033[92m%s\033[0m' % o


import logging
if logger.getEffectiveLevel() != logging.DEBUG:
    LogManager.getLogManager().reset()

class AlertHandler(htmlunit.AlertHandler):
    def handleAlert(self, page, message):
        logger.info('JavaScript alert(%s)', coerce_quote(message))

class ConfirmHandler(htmlunit.ConfirmHandler):
    def handleConfirm(self, page, message):
        logger.info('JavaScript confirm(%s) on %s', coerce_quote(message), coerce_quote(page))
        return True

class BlankWebResponseData(htmlunit.WebResponseData):
    def __init__(self, message):
        htmlunit.WebResponseData.__init__(self, jarray.zeros(0, 'b'), 204, message, [])

class BlankWebResponse(htmlunit.WebResponse):
    def __init__(self, request):
        htmlunit.WebResponse.__init__(self, BlankWebResponseData("skipped %s" % request.getUrl()), request, 0)

    def getStatusCode(self):
        return 204

class LoggingWebConnection(htmlunit.HttpWebConnection):
    def __init__(self, client, filter_request_pattern, filter_password_pattern, got_urls, delete_duplicate_cookies=False):
        htmlunit.HttpWebConnection.__init__(self, client)
        self.client = client
        self.got_urls = got_urls
        self.delete_duplicate_cookies = delete_duplicate_cookies
        self.filter_password_regex = re.compile(filter_password_pattern, re.IGNORECASE)
        self.filter_request_regex = re.compile(filter_request_pattern, re.IGNORECASE) if filter_request_pattern else None
        if self.filter_request_regex:
            logger.debug('filter-request-regex: %s', self.filter_request_regex.pattern)

    #(\.css)|(scriptaculous/)|(cgi-mod/chart\.cgi)
    def getResponse(self, request):
        url = str(request.getUrl())
        if self.filter_request_regex and self.filter_request_regex.search(url):
            logger.debug('%s matches filter-request-regex "%s"', url, self.filter_request_regex.pattern)
            return BlankWebResponse(request)

        self.got_urls.append(url)
        output = []
        output.append('')
        output.append(green('------------- [%s] -------------' % request.getHttpMethod()))
        output.append(url)
        output.append(
            string.join(['%s=%s' % (pair.getName(), '[*FILTERED*]' if self.filter_password_regex.search(pair.getName()) else pair.getValue()) for pair in request.getRequestParameters()], '\n')
        )

        if self.delete_duplicate_cookies:
            cookies = dict((cookie.getName(), cookie) for cookie in self.client.getCookieManager().getCookies())

            self.client.getCookieManager().clearCookies()

            for cookie in cookies.values():
                self.client.getCookieManager().addCookie(cookie)

        logger.info(string.join(output, '\n'))
        response = htmlunit.HttpWebConnection.getResponse(self, request)

        # Changed these three to info, should be debug
        logger.info('Cookies: [%s]', ', '.join('"%s"' % cookie for cookie in self.client.getCookieManager().getCookies()))
        logger.info('Headers >> %s', request.getAdditionalHeaders())
        logger.info('Headers << %s', response.getResponseHeaders())

        return response

def Element(name, attrs={}, text=None):
    element = ElementTree.Element(name, attrs)
    if text:
        element.text = unicode(text)
    return element

class AttachmentHandler(htmlunit.attachment.AttachmentHandler):
    def __init__(self, parent):
        self.parent = parent

    def handleAttachment(self, page):
        attachment = htmlunit.attachment.Attachment(page)
        filename = Spider.temporary_filename()
        Spider.save(attachment.getPage().getWebResponse().getContentAsStream(), filename)
        self.parent.stack[-1].append(Element('attachment', {'filename': attachment.getSuggestedFilename(), 'url': str(page.getUrl())}, text=filename))

class MatchesFunction(org.jaxen.Function):
    def call(self, context, args):
        if len(args) == 2 or len(args) == 3:
            value = org.jaxen.function.StringFunction.evaluate(args.get(0), context.getNavigator())
            pattern = org.jaxen.function.StringFunction.evaluate(args.get(1), context.getNavigator())
            flags = re.U

            if len(args) == 3:
                options = list(org.jaxen.function.StringFunction.evaluate(args.get(2), context.getNavigator()).upper())

                for flag in ('S', 'M', 'I', 'X'):
                    if flag in options:
                        flags |= getattr(re, flag)
                        options.remove(flag)

                if len(options) != 0:
                    raise org.jaxen.FunctionCallException('invalid flags passed to matches().')

            return re.compile(pattern, flags).search(value) is not None
        raise org.jaxen.FunctionCallException("matches() requires two or three arguments.")

class SetFunction(org.jaxen.Function):
    def call(self, context, args):
        if len(args) == 2:
            name = org.jaxen.function.StringFunction.evaluate(args.get(0), context.getNavigator())
            value = org.jaxen.function.StringFunction.evaluate(args.get(1), context.getNavigator())
            setattr(Spider.env, name, value)
            return value
        raise org.jaxen.FunctionCallException("set() requires two arguments.")

class GetFunction(org.jaxen.Function):
    def call(self, context, args):
        if len(args) == 1:
            name = org.jaxen.function.StringFunction.evaluate(args.get(0), context.getNavigator())
            return getattr(Spider.env, name, None)
        raise org.jaxen.FunctionCallException("get() requires one argument.")

for fn, name in ((MatchesFunction, 'matches'), (GetFunction, 'get'), (SetFunction, 'set')):
    org.jaxen.XPathFunctionContext.getInstance().registerFunction(None, name, fn())

def isready(page):
    return not hasattr(page, 'isBeingParsed') or (not page.isBeingParsed() and page.executeJavaScript('document').getJavaScriptResult())

class SpiderNavigator(org.jaxen.dom.DocumentNavigator):
    def getElementName(self, element):
        return org.jaxen.dom.DocumentNavigator.getElementName(self, element).lower()

    def getChildAxisIterator(self, contextNode):
        if isinstance(contextNode, htmlunit.html.HtmlFrame) or isinstance(contextNode, htmlunit.html.HtmlInlineFrame):
            if not isready(contextNode.getEnclosedPage()):
                logger.warning('Page inside %s failed to load', contextNode)
            return java.util.ArrayList(list(contextNode.getEnclosedPage().getChildren())).listIterator()
        return org.jaxen.dom.DocumentNavigator.getChildAxisIterator(self, contextNode)

import threading

class Spider():
    class MetaClass(type):
        def __new__(metaclass, name, bases, attrs):
            cls = type.__new__(metaclass, name, bases, attrs)
            cls.env = threading.local()
            return cls
    __metaclass__ = MetaClass

    RefreshHandlers = {
        'threaded': lambda attrs: htmlunit.ThreadedRefreshHandler(),
        'waiting': lambda attrs: htmlunit.WaitingRefreshHandler(coerce_to_int(attrs.get('page-timeout', '60')) * 1000)
    }

    UserAgents = {
        'chrome': htmlunit.BrowserVersion.CHROME,
        'chrome-16': htmlunit.BrowserVersion.CHROME_16,
        'firefox': htmlunit.BrowserVersion.FIREFOX_3_6,
        'firefox-3': htmlunit.BrowserVersion.FIREFOX_3_6,
        'firefox-3.6': htmlunit.BrowserVersion.FIREFOX_3_6,
        'firefox-17': htmlunit.BrowserVersion.FIREFOX_17,
        'msie': htmlunit.BrowserVersion.INTERNET_EXPLORER_6,
        'msie-6': htmlunit.BrowserVersion.INTERNET_EXPLORER_6,
        'msie-7': htmlunit.BrowserVersion.INTERNET_EXPLORER_7,
        'msie-8': htmlunit.BrowserVersion.INTERNET_EXPLORER_8,
        'msie-9': htmlunit.BrowserVersion.INTERNET_EXPLORER_9
    }

    def evaluate(self, o):
        """
            evaluate an expression or literal value in the context of the current page

                javascript:<value>  - execute value as javascript and return the last referenced value in the string
                xpath: <value>      - execute value as an xpath expression and return the node which it refers to
        """
        value = o
        match = re.match('(xpath|javascript|retrieve):(.*)', o)
        if match:
            value = getattr(self, 'evaluate_%s' % match.group(1))(match.group(2))
            assert value is not None, 'unable to resolve value "%s"' % o
        return Spider.str_element(value)

    def evaluate_retrieve(self, name):
        return self.env.get(name, '')

    def evaluate_xpath(self, xpath):
        return self.find_element(xpath)

    def evaluate_javascript(self, javascript):
        return self.node.executeJavaScript(javascript).getJavaScriptResult()

    @staticmethod
    def str_element(element):
        value = element
        if hasattr(element, 'asXml'): value = element.asXml()
        value = unicode(value).strip()
        return value

    def find_element(self, *args, **kwargs):
        elements = self.find_elements(*args, **kwargs)
        return elements[0] if len(elements) else None

    def find_elements(self, xpath, parent=None, retries=1):
        if isinstance(parent or self.node, htmlunit.UnexpectedPage):
            raise AssertionError('Unable to use xpath %r on page with unexpected content type' % (xpath,))
        if not isinstance(parent or self.node, htmlunit.html.DomNode):
            raise AssertionError('Unable to use xpath %r on non-xml document:\n%s' % (xpath, (parent or self.node).getContent()))

        return org.jaxen.BaseXPath(xpath, SpiderNavigator()).selectNodes(parent or self.node)

    @staticmethod
    def parse(template):
        """
            traverse each node and execute the crawl template

            each node should return either:
                an xml output value     - to be appended into the output document
                a generator expression  - child nodes will be executed on each yield of the generator
                None                    - the document will continue processing


        """
        spider = Spider()

        def _process(element, value):
            if hasattr(value, 'append'):
                spider.stack[-1].append(value)
                spider.stack.append(value)

            for child in element.getchildren():
                _execute(child)

            if hasattr(value, 'append'):
                spider.stack.pop()

        def _execute(element):
            method_name = Spider.method_name(element.tag)
            if not hasattr(spider, method_name):
                raise AttributeError('Unknown tag <%s />' % element.tag)
            try:
                value = getattr(spider, method_name)(element.attrib, element.text)
            except KeyError, e:
                raise AttributeError('Missing attribute "%s" on tag <%s />' % (e.args[0], element.tag))

            if hasattr(value, 'next'):
                # element is a generator, execute child nodes
                for node in value:
                    _process(element, node)
            else:
                _process(element, value)

        try:
            _execute(ElementTree.fromstring(template))
        except Exception, e:
            spider.stack[-1].append(Element('error', {'type': type(e).__name__}, text=unicode(e)))
            try:
                logger.error('Error on Page(%s):\r\n%s', red(spider.url), spider.str_element(spider.page))
            except:
                pass

        document = ElementTree.tostring(spider.root)

        logger.info('\n%s' % document)

        return document

    @property
    def window(self):
        return self.client.getTopLevelWindows()[-1]

    @property
    def page(self):
        return self.window.getEnclosedPage()

    @property
    def url(self):
        return self.page.webResponse.getWebRequest().getUrl()

    @property
    def node(self):
        return self.window.getEnclosedPage() if not len(self.nodes) else self.nodes[-1]

    def __init__(self):
        self.post_data = []
        self.add_headers = []
        self.nodes = []
        self.client = None
        self.request = None
        self.root = Element('return')
        self.stack = [self.root]

    def visit(self, page):
        self.client.waitForBackgroundJavaScript(self.background_javascript_timeout)

        if not isready(page):
            logger.warning('Page inside %s failed to load', self.window)

        job_manager = self.window.getJobManager()
        if job_manager.jobCount > 0:
            logger.warning('%s background jobs are scheduled, the earliest is %s', job_manager.jobCount, job_manager.getEarliestJob())

    def process_sleep(self, attrs, text):
        """
            <sleep seconds="60" />
        """
        time.sleep(coerce_to_int(attrs['seconds']))

    def process_browser(self, attrs, text):
        if self.client is not None:
            raise Exception('template may only contain one browser element')

        self.env = {}

        user_agent_name = attrs.get('user-agent', 'firefox').lower()
        user_agent = Spider.UserAgents.get(user_agent_name, None)

        if not user_agent:
            raise AssertionError('Unknown user-agent %s, available: %s', user_agent, ', '.join(Spider.UserAgents.keys()))

        self.client = htmlunit.WebClient(user_agent)
        self.client.setJavaScriptEnabled(coerce_to_bool(attrs.get('javascript-enabled', 'True')))

        refresh_handler_name = attrs.get('refresh-handler', 'threaded').lower()
        refresh_handler = Spider.RefreshHandlers.get(refresh_handler_name.lower(), lambda attrs: None)(attrs)

        if not refresh_handler:
            raise AssertionError('Unknown refresh-handler %s, available: %s', refresh_handler_name, ', '.join(Spider.RefreshHandlers.keys()))

        self.client.setRefreshHandler(refresh_handler)
        # self.client.setRefreshHandler(htmlunit.WaitingRefreshHandler(coerce_to_int(attrs.get('page-timeout', '60')) * 1000))

        self.client.setAttachmentHandler(AttachmentHandler(self))
        #self.client.setIncorrectnessListener(IgnoreIncorrectnessListener())
        if coerce_to_bool(attrs.get('synchronize-ajax', False)):
            self.client.setAjaxController(htmlunit.NicelyResynchronizingAjaxController())
        self.got_urls = []
        self.client.setWebConnection(LoggingWebConnection(
            self.client,
            attrs.get('filter-request-regex', '\.css$'),
            attrs.get('filter-password-regex', 'pass(w(or)?d)?'),
            self.got_urls,
            coerce_to_bool(attrs.get('delete-duplicate-cookies', False))
        ))
        self.client.setThrowExceptionOnScriptError(False)
        self.client.setThrowExceptionOnFailingStatusCode(False)
        self.client.setPrintContentOnFailingStatusCode(False)
        self.client.setAlertHandler(AlertHandler())
        self.client.setConfirmHandler(ConfirmHandler())
        self.client.setRedirectEnabled(True)
        self.client.setJavaScriptTimeout(coerce_to_int(attrs.get('javascript-timeout', '60')) * 1000)
        self.client.setTimeout(coerce_to_int(attrs.get('page-timeout', '60')) * 1000)
        self.background_javascript_timeout = coerce_to_int(attrs.get('background-javascript-timeout', '2')) * 1000

        use_insecure_ssl = coerce_to_bool(attrs.get('use-insecure-ssl', False))
        ssl_protocols = filter(bool, map(string.strip, attrs.get('ssl-protocols', '').split(','))) or ['SSLv3']
        self.client.setUseInsecureSSL(use_insecure_ssl)

        if use_insecure_ssl:
            ssl_utilities.use_insecure_ssl(self.client, ssl_protocols)
        else:
            ssl_utilities.use_secure_ssl(self.client, ssl_protocols)

    def process_store(self, attrs, text):
        """
            <store name="NAME" value="VALUE" />

        """
        self.env[attrs['name']] = self.evaluate(attrs['value'])

    def process_http_basic_authentication(self, attrs, text):
        """
            <http-basic-authentication username="USERNAME" password="PASSWORD" />

            provide basic credentials to each page visited by this browser
        """
        self.client.getCredentialsProvider().setCredentials(
            auth.AuthScope(auth.AuthScope.ANY_HOST, auth.AuthScope.ANY_PORT),
            auth.UsernamePasswordCredentials(attrs['username'], attrs['password'])
        )

    def is_success(self, attrs, text):
        xpath = attrs['xpath']

        elements = self.find_elements(xpath)

        if not elements: return False

        regex = attrs.get('regex', None)
        if regex:
            pattern = re.compile(regex)
            for element in elements:
                return pattern.search((element.asText() if hasattr(element, 'asText') else str(element)).strip())

        return True

    def process_javascript(self, attrs, text):
        """
            <javascript>
                <![CDATA[

                ]]>
            </javascript>

            A script to be run against the currently active page. Typically used
            as a clause for an until loop or to do some dom manipulation.

        """
        result = self.node.executeJavaScript(text)
        page = result.getNewPage()
        assert page, 'JavaScript closed page.'
        self.visit(page)

    def process_until(self, attrs, text):
        """
            <until xpath="XPATH">
                ...
            </until>

            loops until XPATH describes an element inside the document
            or the page has not changed in an interation. (to guard against infinite
            loops)

        """
        while not self.is_success(attrs, text):
            yield

    def process_if(self, attrs, text):
        """
            <if xpath="XPATH">
                ...
            </if>

            executes if XPATH describes an element inside the document

        """
        if self.is_success(attrs, text):
            yield

    def process_unless(self, attrs, text):
        if not self.is_success(attrs, text):
            yield

    def process_while(self, attrs, text):
        """
            <while xpath="XPATH">
                ...
            </while>

            loops while XPATH describes an element inside the document
            or the page has not changed in an interation. (to guard against infinite
            loops)

        """
        while self.is_success(attrs, text):
            yield

    def process_echo_tag(self, attrs, text):
        """
            <echo output="OUTPUT" />

            Used to insert arbitrary tags into the output document. Can be useful
            for structuring output data.

            <OUTPUT />
        """
        return Element(attrs['output'], text=text)

    def process_echo_element(self, attrs, text):
        """
            <echo-element output="OUTPUT" xpath="XPATH" />

            output the xml element in the form:

            <value name="{{ OUTPUT }}">{{ first element matching XPATH }}</value>
        """
        xpath = attrs['xpath']

        element = self.find_element(xpath)

        assert element != None, 'no element found @ %s' % xpath

        logger.info(('\n<echo-element output="%s" />\n' % attrs['output']) + Spider.str_element(element))

        return Element('value', {'name': attrs['output']}, text=Spider.str_element(element))

    def process_echo_elements(self, attrs, text):
        """
            <elements xpath="XPATH" output="OUTPUT">
                ...
            </elements>

            executes all subchildren once for each node matching XPATH in the document and also outputs
            the matching xpath value.

            <element output="OUTPUT" value="...">...</element>
        """
        xpath = attrs['xpath']

        elements = self.find_elements(xpath)

        logger.info(('\n<echo-elements output="%s" />\n' % attrs['output']) + '\n'.join(Spider.str_element(element) for element in elements))

        for element in elements:
            self.nodes.append(element)
            yield Element('element', {'name': attrs['output']})
            assert self.nodes, 'unexpectedly changed page during <echo-elements /> element'
            assert self.nodes[-1] == element, "unexpected element '%s' added to context during <echo-elements /> element" % self.nodes[-1]
            self.nodes.pop()

    def process_echo_url(self, attrs, text):
        """
            <echo-url output="OUTPUT" />

            prints the active page's url

            <url name="OUTPUT">...</url>
        """
        return Element('url', {'name': attrs['output']}, text=unicode(self.window.getEnclosedPage().webResponse.getWebRequest().getUrl()))

    def process_echo_headers(self, attrs, text):
        """
            <echo-headers output="OUTPUT" name="NAME (regex)" />

            prints headers matching the regular expression NAME

            <headers name="OUTPUT">
                <header>...</header>
            </headers>
        """
        headers = self.node.webResponse.getResponseHeaders()
        parent = Element('headers', {'name': attrs['output']})

        for pair in headers:
            pattern = re.compile(attrs['name'], re.IGNORECASE)
            if pattern.search(pair.getName()):
                child = Element('header', text=string.join((pair.getName(), pair.getValue()), ' '))
                parent.append(child)

        return parent

    def process_echo_cookies(self, attrs, text):
        """
            <echo-cookies output="OUTPUT" />

            prints any cookies accumulated to this point

            <cookies name="OUTPUT">
                <cookie></cookie>
            </cookies>
        """
        cookie_manager = self.client.getCookieManager()
        parent = Element('cookies', {'name': attrs['output']})

        for cookie in cookie_manager.getCookies():
            parent.append(Element('cookie', text=cookie.toString()))

        return parent

    def process_get(self, attrs, text):
        """
            <get url="URL" />

            do a manual HTTP get request to the requested URL
        """
        self.visit(self.client.getPage(self.evaluate(attrs['url'])))

    def process_post(self, attrs, text):
        """
            <post url="URL" />

            do a manual post request to the requested URL. combine this with post-data to set specific post
            parameters
        """
        request_settings = htmlunit.WebRequest(java.net.URL(self.evaluate(attrs['url'])), htmlunit.HttpMethod.POST)
        self.post_data.append([])
        yield None
        request_settings.setRequestParameters(self.post_data[-1])
        if self.add_headers:
            for header in self.add_headers:
                request_settings.setAdditionalHeader(header[0], header[1])
        self.post_data.pop()
        self.visit(self.client.getPage(request_settings))

    def process_post_data(self, attrs, text):
        """
            <post-data name="NAME" value="VALUE" />

            set post data to be sent in the parent post request.

            both NAME and VALUE can be expressions starting with xpath: or javascript: which will be executed in the
            context of the current page and inserted into the parameter
        """
        self.post_data[-1].append(htmlunit.util.NameValuePair(self.evaluate(attrs['name']), self.evaluate(attrs['value'])))

    def process_add_header(self, attrs, text):
        """
            <add-header name="NAME" value="VALUE" />

            add a header to be sent in the parent post request.

            both NAME and VALUE can be expressions starting with xpath: or javascript: which will be executed in the
            context of the current page and inserted into the parameter
        """
        self.add_headers.append([self.evaluate(attrs['name']), self.evaluate(attrs['value'])])

    def process_add_cookie(self, attrs, text):
        """
            <add-cookie name="NAME" value="VALUE" domain="DOMAIN" />

            add a cookie to be sent in the requests.

        """
        cookie = htmlunit.util.Cookie(
            self.evaluate(attrs['domain']),
            self.evaluate(attrs['name']),
            self.evaluate(attrs['value'])
        )
        self.client.getCookieManager().addCookie(cookie)

    def process_success(self, attrs, text):
        """
            <success xpath="XPATH" regex="REGEX" value="VALUE">MESSAGE</success>

            or

            <success url_regex="REGEX">MESSAGE</success>

            Specify an element which must exist on this page in order for processing to continue.
            Optionally specify a regular expression it must match.
            Alternatively specifiy a URL that must have been retrieved by a GET for a success.

        """
        url_regex = attrs.get('url_regex', None)
        if url_regex:
            pattern = re.compile(url_regex)
            success = False
            for url in self.got_urls:
                if pattern.search(url):
                    success = True
            assert success, 'success url_regex "%s" not found' % url_regex
        else:
            xpath = attrs['xpath']

            elements = self.find_elements(xpath)

            assert elements, 'unable to find elements @ "%s"' % xpath

            regex = attrs.get('regex', None)
            if regex:
                pattern = re.compile(regex)
                for element in elements:
                    element_text = element.asText().strip()
                    assert pattern.search(element_text), text or "'%s' != /%s/" % (element_text, regex)

    def process_failure(self, attrs, text):
        """
            <failure xpath="XPATH" regex="REGEX">MESSAGE</failure>

            or

            <failure url_regex="REGEX">MESSAGE</failure>

            Specify an element which must not exist on this page in order for processing to continue.
            Optionally specifiy a regular expression which it must not match.
            Alternatively specifiy a URL that must not have been retrieved by a GET for a failure.
        """
        url_regex = attrs.get('url_regex', None)
        if url_regex:
            pattern = re.compile(url_regex)
            failure = False
            for url in self.got_urls:
                if pattern.search(url):
                    failure = True
            assert not failure, 'failure url_regex "%s" found' % url_regex
        else:
            xpath = attrs['xpath']
            elements = self.find_elements(xpath)
            message = self.evaluate(attrs['value']) if 'value' in attrs else text
            regex = attrs.get('regex', None)

            if regex:
                pattern = re.compile(regex)
                for element in elements:
                    element_text = element.asText().strip()
                    if pattern.search(element_text):
                        yield None
                        raise AssertionError(message or "'%s' == /%s/" % (element_text, regex))
            elif elements:
                yield None
                raise AssertionError(message or 'found the failure element @ %s' % xpath)

    def process_form(self, attrs, text):
        """
            <form xpath="XPATH"></form>

            asserts that the an element exists at the specified XPATH and it is a form
        """
        xpath = attrs['xpath']

        form = self.find_element(xpath)

        assert form, "unable to find element @ '%s'" % xpath
        assert isinstance(form, htmlunit.html.HtmlForm), "unable to find <form /> element @ '%s'" % xpath

        self.nodes.append(form)
        yield None
        assert self.nodes, 'unexpectedly changed page during <form /> element'
        assert self.nodes[-1] == form, "unexpected element '%s' added to context during <form /> element" % self.nodes[-1]
        self.nodes.pop()

    def process_click(self, attrs, text):
        """
            <click xpath="XPATH" />

            trigger the click event on the first element described by xpath.

        """
        xpath = attrs['xpath']

        element = self.find_element(xpath)

        assert element, "unable to find element @ '%s'" % xpath
        assert hasattr(element, 'click'), 'element does not have click attribute'

        self.visit(element.click())

    def process_checkbox(self, attrs, text):
        xpath = attrs['xpath']

        elements = self.find_elements(xpath)

        assert elements, "unable to find elements @ '%s'" % xpath

        for element in elements:
            assert isinstance(element, htmlunit.html.HtmlCheckBoxInput), "checkbox expected @ '%s' found %s" % (xpath, element)

            element.setChecked(coerce_to_bool(attrs['checked']))

    def process_radio_button(self, attrs, text):
        xpath = attrs['xpath']

        elements = self.find_elements(xpath)

        assert elements, "unable to find elements @ '%s'" % xpath

        for element in elements:
            assert isinstance(element, htmlunit.html.HtmlRadioButtonInput), "radio button expected @ '%s' found %s" % (xpath, element)

            element.setChecked(coerce_to_bool(attrs['checked']))

    def process_input(self, attrs, text):
        """
            <input xpath="XPATH" value="VALUE" />

            fill in the form element described by XPATH with the expression VALUE.
        """
        xpath = attrs['xpath']

        elements = self.find_elements(xpath)
        value = self.evaluate(attrs['value'])

        assert elements, "unable to find element @ '%s'" % xpath

        for element in elements:
            logger.info(Spider.str_element(element))

            assert isinstance(element, htmlunit.html.HtmlInput), "input expected @ '%s' found %s" % (xpath, element)

            element.setValueAttribute(value)

    def process_textarea(self, attrs, text):
        """
            <textarea xpath="XPATH" value="VALUE" />

            fill in the form element described by XPATH with the expression VALUE.
        """
        xpath = attrs['xpath']

        elements = self.find_elements(xpath)
        value = self.evaluate(attrs['value'])

        assert elements, "unable to find element @ '%s'" % xpath

        for element in elements:
            logger.info(Spider.str_element(element))

            assert isinstance(element, htmlunit.html.HtmlTextArea), "textarea expected @ '%s' found %s" % (xpath, element)

            element.setText(value)

    def process_select(self, attrs, text):
        """
            <select xpath="XPATH" value="VALUE" />

            fill in the form element described by XPATH with the expression VALUE.
        """
        xpath = attrs['xpath']

        elements = self.find_elements(xpath)
        value = self.evaluate(attrs['value'])
        quoted = coerce_quote(value)

        assert elements, "unable to find element @ '%s'" % xpath

        logger.debug("Using the following as value in select dropdown : .//option[@value=%s]" % (quoted,))

        for element in elements:
            logger.info(Spider.str_element(element))

            assert isinstance(element, htmlunit.html.HtmlSelect), "select expected @ '%s' found %s" % (xpath, element)
            assert self.find_element(".//option[@value=%s]" % (quoted,), parent=element), "unable to find select option with value %s" % (quoted,)

            element.setSelectedAttribute(value, True)

    @staticmethod
    def save(input_stream, filename):
        source = java.nio.channels.Channels.newChannel(input_stream)
        destination = java.io.FileOutputStream(java.io.File(filename)).getChannel()

        try:
            offset = 0
            while True:
                written = destination.transferFrom(source, offset, 4096)
                if written == 0:
                    break
                offset += written
        finally:
            destination.close()

    def process_back(self, attrs, text):
        self.window.getHistory().back()

    def process_save(self, attrs, text):
        """
            <save xpath="XPATH" output="OUTPUT" path="PATH" />

            download the linked target and save the path of the stored file in the download element named OUTPUT.

            <save name="OUTPUT">LOCAL FILENAME</save>
        """
        xpath = attrs['xpath']

        element = self.find_element(xpath)

        assert element != None, 'no element found @ %s' % xpath

        page = element.click()

        assert page != None, 'nothing returned when clicking %s' % xpath

        if 'path' in attrs:
            assert attrs['path'], 'Invalid path attribute %r on <save /> tag' % (attrs['path'],)
            filename = Spider.fixed_filename(attrs['path'])
        else:
            filename = Spider.temporary_filename()

        Spider.save(self.node.getWebResponse().getContentAsStream(), filename)

        # self.visit(page)

        return Element('save', {'name': attrs['output']}, text=filename)

    @staticmethod
    def fixed_filename(filename):
        dir = os.path.dirname(filename)
        try:
            os.makedirs(dir)
        except os.error, e:
            if e.errno != errno.EEXIST:
                raise

        open(filename, 'a').close()
        return filename

    @staticmethod
    def temporary_filename():
        dir = os.path.join(tempfile.gettempdir(), 'spider')
        try:
            os.makedirs(dir)
        except os.error, e:
            if e.errno != errno.EEXIST:
                raise

        with tempfile.NamedTemporaryFile(dir=dir) as f:
            return f.name

    @staticmethod
    def method_name(name):
        output = []
        name = re.sub('[-:]', '_', name)
        output.append('process')
        output.append(name)
        return string.join(output, '_')
