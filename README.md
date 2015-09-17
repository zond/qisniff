# qisniff

qisniff sniffs for quantum injection (http://blog.fox-it.com/2015/04/20/deep-dive-into-quantum-insert/).

It does this by assembling the streams in temporary files, and comparing incoming packets covering already received
segments of the stream with the already received data.

Differences in this data is indicative of trickery.

Tools that can detect this are relatively rare.

Fox IT (see link above) devised a potential detection method, but state

----
###Evasion

Note that these detection methods are possibly not evasion proof, one could also easily spoof a FIN packet after the QI packet to close the session. This would stop tracking the TCP segments in most IDS systems. Later packets in this stream will not be matched with previous packets.

Other possibilities is to try to create a partial overlap of data, thus avoiding detection of duplicate sequence numbers.

----

qisniff doesn't close sessions at FIN packets, and it doesn't use sequence numbers directly to detect overlaps, so qisniff will detect *all* incoming QI packet insertions.

## Docs

http://godoc.org/github.com/zond/qisniff/qilib

## Usage

```
go get github.com/zond/qisniff
qisniff -file=file.pcap
qisniff -dev=en0
```

## Example run

Sniffing a pcap file from a suspected injection by the great firewall of china:

```
$go run qisniff.go -file eureka.tcpdump 
\ 
123.125.115.164:80(http)->192.150.187.17:31161 1487292510
<A>
HTTP/1.1 200 OK
Server: Apache
Connection: close
Content-Type: text/javascript
Content-Length: 1130


eval(function(p,a,c,k,e,r){e=function(c){return(c<a?'':e(parseInt(c/a)))+((c=c%a)>35?String.fromCharCode(c+29):c.toString(36))};if(!''.replace(/^/,String)){while(c--)r[e(c)]=k[c]||e(c);k=[function(e){re
</A>
<B>
HTTP/1.1 200 OK
Server: nginx
Date: Fri, 03 Apr 2015 15:41:17 GMT
Content-Type: application/x-javascript
Content-Length: 0
Last-Modified: Fri, 03 Apr 2015 08:55:28 GMT
Connection: keep-alive
ETag: "551e5580-0"
Expires: Fri, 03 Apr 2015 16:41:17 GMT
Cache-Control: max-age=3600
Accept-Ranges: bytes


</B>
```

Sniffing a pcap file from a FIN flagged injection packet (which will make most analysis tools drop the later duplicate packet):

```
$go run qisniff.go -file linkedin_FIN.pcap 
/ 
91.225.248.129:80(http)->10.0.1.4:54015 4114717474
<A>
HTTP/1.1 302 Found
Location: http://fox-it.com/
Content-Length: 0


</A>
<B>
HTTP/1.1 301 Moved Permanently
Date: Tue, 21 Apr 2015 00:40:01 GMT
X-
</B>
```

