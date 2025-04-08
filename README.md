HTTP PCAP Extractor
----------------------------------------------------------------
This is a simple Go application for analyzing HTTP traffic from .pcap and .pcapng files. It focuses on extracting HTTP GET requests and matching HTTP responses over TCP, calculating response times, and aggregating the results per URL and time interval.

Features:
----------------------------------------------------------------
 - Parses .pcap or .pcapng files to extract TCP packets.
 - Detects HTTP GET requests and matching HTTP responses.
 - Tracks connection metadata:
    - Source and destination IPs and ports
    - Request and response timestamps
    - Full request URL
 - Calculates response time per connection.
 - Aggregates statistics per minute (or user-defined interval) per URL:
    - Number of connections
    - Average response time
 - Displays results in a formatted table.

Installation:
----------------------------------------------------------------
    go install github.com/google/gopacket@latest
    go build -o http_extractor

Usage:
----------------------------------------------------------------

./http_extractor --interval=[aggregation_interval_seconds] <capture file>
<capture file> – path to your .pcap or .pcapng file.
[aggregation_interval_seconds] – optional argument to define the aggregation time interval (default: 60 seconds).


Output Example:
----------------------------------------------------------------
1 [2025-04-08T06:37:44Z] 2a00:a040:199:3843:c86f:1061:50c9:afc6:35998 -> 2600:1406:bc00:17::6007:8128:80 | 222.030691ms | http://example.org/
2 [2025-04-08T06:37:46Z] 2a00:a040:199:3843:c86f:1061:50c9:afc6:50236 -> 2600:1406:bc00:17::6007:810d:80 | 276.71986ms | http://example.org/
3 [2025-04-08T06:37:51Z] 2a00:a040:199:3843:c86f:1061:50c9:afc6:55920 -> 2600:1406:3a00:21::173e:2e66:80 | 378.203415ms | http://example.com/
4 [2025-04-08T06:37:57Z] 2a00:a040:199:3843:c86f:1061:50c9:afc6:57180 -> 2600:1406:bc00:53::b81e:94ce:80 | 227.563309ms | http://example.com/
5 [2025-04-08T06:37:58Z] 2a00:a040:199:3843:c86f:1061:50c9:afc6:35712 -> 2600:1406:3a00:21::173e:2e65:80 | 207.943493ms | http://example.com/


Aggregated Connections by URL per Interval:
Timestamp            | URL                                     | Connections No.  | Average Response Time
-----------------------------------------------------------------------------------------------
2025-04-07 06:37     |                                          |                  | 
                     | http://example.org/                      | 2                | 249.3755ms
                     | http://example.com/                      | 3                | 271.236666ms


Notes:
----------------------------------------------------------------
Only TCP traffic is analyzed.
UDP and other protocols are ignored.
Requests without a Host header or malformed payloads are skipped.
Responses that do not contain 200 OK are ignored.
Matched request entries are removed after processing to prevent memory growth.

License:
----------------------------------------------------------------
MIT License

Conclusion:
----------------------------------------------------------------
This tool allows you to easily parse .pcap and .pcapng files, extract relevant HTTP data, and perform aggregation on connections. It can be useful for analyzing network traffic, investigating performance issues, and obtaining detailed connection statistics.

Future enhancements:
----------------------------------------------------------------
 - Logging and Debugging: Add logging and debug capabilities to capture detailed information about packet processing, unmatched requests, and errors for better troubleshooting.
 - Handle Segmented Packets: Implement functionality to reassemble fragmented packets, ensuring that multi-segmented HTTP responses are correctly processed.
 - Improved Error Handling: Enhance error detection and reporting to ensure clearer messages during packet parsing, especially for malformed or incomplete HTTP requests/responses.
 - Enhanced Output Options: Provide support for outputting the results to various file formats (e.g., CSV, TXT, JSON) for easier storage, further analysis, or integration with other tools.
  - Performance optimizations: Packet Processing Parallelization; consider Memory Pooling to reduce memory allocation overhead during packet processing.