#! /usr/bin/python3.6

import sys
import os
from tqdm import tqdm
import requests
import dns.resolver


class Dns:
    """
    This class is used to perform Domain Name Server related functions

    """
    _domain = None
    _nameserver = []
    _sub_domains = []
    _shared_domains = ''
    _scraped_urls = []

    def __init__(self):
        if os.name == "posix":
            print("DOMAIN NAME SCANNER v1.0")
            self._domain = input("Enter The domain to scan : ")
        else:
            print("DNS module currently supports Linux Platform only !")
            sys.exit(1)

    """
    This method is used to find the dns servers of a domain
    @:param domain name
    @:return Returns a list of nameservers
    """
    def _dnsenum(self):
        try:
            ns = dns.resolver.query(self._domain, "NS")
            for server in ns:
                self._nameserver.append(server)
        except dns.exception.Timeout:
            self._nameserver = None
            pass

        return self._nameserver

    def _sdomains(self):
        for server in self._dnsenum():
            url = 'http://api.hackertarget.com/findshareddns/?q=%s' % server
            r = requests.get(url, stream=True)
            size = int(r.headers.get('content-length', 0))
            for d in tqdm(r.iter_content(32 * 1024), total=size, unit='B', unit_scale=True,
                          desc="Found .. ", dynamic_ncols=75):
                decoded_sd = d.decode(encoding='UTF-8')
                self._shared_domains += decoded_sd
        return self._shared_domains

    """
    This method will scan for the subdomain
    @:param Type of the scanning.
    @:param Domain name    
    @:return Returns a list of subdomains 
    """
    def _sub_domain_scanner(self):
        url = 'http://api.hackertarget.com/hostsearch/?q=%s' % self._domain
        r = requests.get(url, stream=True)
        size = int(r.headers.get('content-length', 0))
        for d in tqdm(r.iter_content(3 * 1024), total=size, unit='B', unit_scale=True, desc="Found .. ",
                      dynamic_ncols=75):
            decoded_d = d.decode(encoding='UTF-8')
            self._sub_domains.append(decoded_d)
        self._sub_domains = ('\n'.join(self._sub_domains))
        return self._sub_domains

    """
    This method Scraps the urls in the Target page 
    Requires <lynx> to be installed
    can be installed by apt-get install lynx 
    """
    def _scrap_urls(self):
        lynxcmd = "lynx -listonly -dump %s" % self._domain
        data = os.popen(lynxcmd).read()
        self.scraped_urls = data
        return self.scraped_urls

    def print_result(self):
        print("\nNAME SERVERS                      ============================>\n")
        if self._dnsenum():
            for i in self._dnsenum():
                print(i)
        else:
            print("Name Servers not found !")
        print("\n \nSUBDOMAIN : IP ADDRESS         ============================>\n")
        sub = (self._sub_domain_scanner())
        print('  : '.join(sub.split(',')))
        print("\n \nSHARED DOMAINS                 ============================>\n")
        shared = (self._sdomains())
        print(shared)
        print("\n \nSCRAPING URLS :                ============================>\n")
        print(self._scrap_urls())


if __name__ == "__main__":
    target = Dns()
    target.print_result()
