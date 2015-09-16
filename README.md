# qisniff

qisniff sniffs for quantum injection (http://www.wired.com/2014/03/quantum/).

It does this by assembling the streams in temporary files, and comparing incoming packets covering already received
segments of the stream with the already received data.

Differences in this data is indicative of trickery.

## Usage

 go get github.com/zond/qisniff
 qisniff -file=file.pcap
 qisniff -dev=en0

## TODO

- Make the -dev mode warn when the injection happens, instead of at exit.
- Clean up old streams after n seconds to avoid filling the drive.
