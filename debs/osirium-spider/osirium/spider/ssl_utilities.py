from java.security import SecureRandom
from javax.net.ssl import SSLContext, X509TrustManager, TrustManagerFactory

from org.apache.http.conn.scheme import Scheme
import org.apache.http.conn.ssl.AllowAllHostnameVerifier
import org.apache.http.conn.ssl.SSLSocketFactory

# SSL workarounds for various problems
# http://yuriytkach.blogspot.com/2011/10/javaxnetsslsslexception-badrecordmac.html

def SSLSocketFactory(protocols):
    class SSLSocketFactory(org.apache.http.conn.ssl.SSLSocketFactory):
        def createSocket(self, *args):
            socket = org.apache.http.conn.ssl.SSLSocketFactory.createSocket(self, *args)
            socket.setEnabledProtocols(protocols)
            return socket
    return SSLSocketFactory

class FakeX509TrustManager(X509TrustManager):
    def checkClientTrusted(self, chain):
        pass

    def checkServerTrusted(self, *args, **kwargs):
        pass

    def getAcceptedIssuers(self):
        return []

def DefaultTrustManager():
    trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    trustManagerFactory.init(None)
    for trustManager in trustManagerFactory.getTrustManagers():
        if isinstance(trustManager, X509TrustManager):
            return trustManager
    return None

DefaultTrustManager = DefaultTrustManager()

def use_secure_ssl(client, protocols):
    context = SSLContext.getInstance('SSL')
    context.init(None, [DefaultTrustManager], SecureRandom())
    factory = SSLSocketFactory(protocols)(context)
    https = Scheme('https', factory, 443)
    schemeRegistry = client.getWebConnection().getHttpClient().getConnectionManager().getSchemeRegistry()
    schemeRegistry.register(https)

def use_insecure_ssl(client, protocols):
    """Installs a fake trust manager and hostname verifier on an HTMLUnit
    WebClient, ensuring that it will never balk at poorly set up SSL
    servers.
    """
    context = SSLContext.getInstance('SSL')
    context.init(None, [FakeX509TrustManager()], SecureRandom())
    # Normal factory with SSLv2Hello, SSLv3, TLSv1 enabled
    factory = SSLSocketFactory(protocols)(context)
    factory.setHostnameVerifier(org.apache.http.conn.ssl.AllowAllHostnameVerifier())
    https = Scheme('https', factory, 443)
    schemeRegistry = client.getWebConnection().getHttpClient().getConnectionManager().getSchemeRegistry()
    schemeRegistry.register(https)
