from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.ldapclient import LDAPClient
from ldaptor.protocols.ldap.ldapconnector import connectToLDAPEndpoint
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer, protocol, reactor
from twisted.python import log
from functools import partial
from ldaptor.protocols import pureldap
from ldaptor.protocols.ldap.proxybase import ProxyBase
from twisted.internet import defer
from twisted.python import log
from ldaptor import ldapfilter
import sys

basura_inicio = [
    ldapfilter.parseFilter('(foo=nope1)'),
    ldapfilter.parseFilter('(nonexistent1=*)'),
    ldapfilter.parseFilter('(bar=nope2)'),
    ldapfilter.parseFilter('(nonexistent2=*)'),
    ldapfilter.parseFilter('(baz=nope3)'),
]

basura_final = [
    ldapfilter.parseFilter('(xyz=nope4)'),
    ldapfilter.parseFilter('(nonexistent3=*)'),
    ldapfilter.parseFilter('(abc=nope5)'),
    ldapfilter.parseFilter('(nonexistent4=*)'),
    ldapfilter.parseFilter('(def=nope6)'),
]

basura = (basura_inicio + basura_final) * 20


class LoggingProxy(ProxyBase):
    def handleBeforeForwardRequest(self, request, controls, reply):
        if isinstance(request, pureldap.LDAPSearchRequest):
            #log.msg(f"[+] Original filter: {repr(request.filter)}")

            if isinstance(request.filter, pureldap.LDAPFilter_or):
                filtro_real = request.filter.data
            else:
                filtro_real = [request.filter]

            request.filter = pureldap.LDAPFilter_or(
                basura_inicio + basura + filtro_real + basura_final + basura)

            #log.msg(
            #    f"[+] Modified filter with garbage OR: {repr(request.filter)}")

        return defer.succeed((request, controls))

    def handleProxiedResponse(self, response, request, controls):
        #log.msg(f"[+] Request => {repr(request)}")
        #log.msg(f"[+] Response => {repr(response)}")
        return defer.succeed(response)


def ldapBindRequestRepr(self):
    l = []
    l.append('version={0}'.format(self.version))
    l.append('dn={0}'.format(repr(self.dn)))
    l.append('auth=****')
    if self.tag != self.__class__.tag:
        l.append('tag={0}'.format(self.tag))
    l.append('sasl={0}'.format(repr(self.sasl)))
    return self.__class__.__name__ + '(' + ', '.join(l) + ')'


pureldap.LDAPBindRequest.__repr__ = ldapBindRequestRepr


if __name__ == '__main__':
    log.startLogging(sys.stderr)
    factory = protocol.ServerFactory()
    proxiedEndpointStr = 'tcp:host=10.10.11.76:port=389'
    use_tls = False
    clientConnector = partial(
        connectToLDAPEndpoint,
        reactor,
        proxiedEndpointStr,
        LDAPClient)

    def buildProtocol():
        proto = LoggingProxy()
        proto.clientConnector = clientConnector
        proto.use_tls = use_tls
        return proto

    factory.protocol = buildProtocol
    reactor.listenTCP(389, factory)
    reactor.run()
