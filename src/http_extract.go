package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"encoding/binary"

	"hash/fnv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

// HTTPRequest holds the initial GET request info
type HTTPRequest struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	RequestTime      time.Time
	URL              string
}

// HTTPConnect stores completed connection data with response info
type HTTPConnect struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	ConnectionTime   time.Time
	ResponseTime     time.Duration
	URL              string
}

// aggrConn aggregates multiple HTTPConnects over a time interval and URL
type aggrConn struct {
	intervalStartTS time.Time
	URL             string
	avgResponse     time.Duration
	numOfConns      uint64
}

var requestMap = map[uint64]HTTPRequest{}
var connectionMap = map[uint64][]HTTPConnect{}
var aggregateMap = map[string]*aggrConn{}
var aggregateList []*aggrConn
var aggregationInterval time.Duration
var connection_cnt = 1

func main() {
	var intervalSec int
	flag.IntVar(&intervalSec, "interval", 60, "Aggregation interval in seconds")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Println("Usage: go run http_extract.go [--interval=N] <caprure file>")
		os.Exit(1)
	}

	pcapFilePath := flag.Arg(0)
	aggregationInterval = time.Duration(intervalSec) * time.Second

	// Open and parse the pcap file
	pcapFile, err := os.Open(pcapFilePath)
	if err != nil {
		log.Fatalf("Error opening pcap file: %v", err)
	}
	defer pcapFile.Close()

	// Determine the file format by reading the first 4 bytes (magic number)
	var magicNumber uint32
	err = binary.Read(pcapFile, binary.LittleEndian, &magicNumber)
	if err != nil {
		log.Fatalf("Error reading file header: %v", err)
	}

	// Reset file pointer after reading the header
	_, err = pcapFile.Seek(0, 0)
	if err != nil {
		log.Fatalf("Error resetting file pointer: %v", err)
	}

	// Define packetSource as a pointer to gopacket.PacketSource
	var packetSource *gopacket.PacketSource

	switch magicNumber {
	case 0xa1b2c3d4: // PCAP format
		reader, err := pcapgo.NewReader(pcapFile)
		if err != nil {
			log.Fatalf("Error reading pcap file: %v", err)
		}
		packetSource = gopacket.NewPacketSource(reader, reader.LinkType())
	case 0x0a0d0d0a: // PCAPNG format
		reader, err := pcapgo.NewNgReader(pcapFile, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			log.Fatalf("Error reading pcapng file: %v", err)
		}
		packetSource = gopacket.NewPacketSource(reader, reader.LinkType())
	default:
		log.Fatalf("Unknown magic number (not a valid pcap/pcapng file)")
	}

	// Process the packets
	for packet := range packetSource.Packets() {
		processPacket(packet)
	}

	printAggregateList()
}

// aggregateConnections groups connection data into time buckets for aggregation
func aggregateConnections(conn HTTPConnect, urlHash uint64) {
	interval := conn.ConnectionTime.Truncate(aggregationInterval)
	key := fmt.Sprintf("%d|%d", interval.Unix(), urlHash)

	if aggr, exists := aggregateMap[key]; exists {
		aggr.numOfConns++
		totalResp := aggr.avgResponse*time.Duration(aggr.numOfConns-1) + conn.ResponseTime
		aggr.avgResponse = totalResp / time.Duration(aggr.numOfConns)
	} else {
		newAggr := &aggrConn{
			intervalStartTS: interval,
			URL:             conn.URL,
			avgResponse:     conn.ResponseTime,
			numOfConns:      1,
		}
		aggregateMap[key] = newAggr
		aggregateList = append(aggregateList, newAggr)
	}
}

// processPacket filters and handles only HTTP traffic from TCP packets
func processPacket(packet gopacket.Packet) {
	app := packet.ApplicationLayer()
	if app == nil {
		return
	}
	payload := app.Payload()

	netLayer := packet.NetworkLayer()
	transportLayer := packet.TransportLayer()
	if netLayer == nil || transportLayer == nil {
		return
	}

	ipv4, _ := netLayer.(*layers.IPv4)
	ipv6, _ := netLayer.(*layers.IPv6)
	tcp, _ := transportLayer.(*layers.TCP)
	if tcp == nil {
		return
	}

	srcIP := ""
	dstIP := ""
	if ipv4 != nil {
		srcIP = ipv4.SrcIP.String()
		dstIP = ipv4.DstIP.String()
	} else if ipv6 != nil {
		srcIP = ipv6.SrcIP.String()
		dstIP = ipv6.DstIP.String()
	}

	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)
	timestamp := packet.Metadata().Timestamp

	payloadStr := string(payload)
	if strings.HasPrefix(payloadStr, "GET ") && strings.Contains(payloadStr, "HTTP/") {
		handleRequest(payloadStr, srcIP, srcPort, dstIP, dstPort, timestamp)
	} else if strings.HasPrefix(payloadStr, "HTTP/") && strings.Contains(payloadStr, "200 OK") {
		handleResponse(payloadStr, srcIP, srcPort, dstIP, dstPort, timestamp)
	}
}

// handleRequest extracts GET request and adds it to requestMap
func handleRequest(payload, srcIP string, srcPort uint16, dstIP string, dstPort uint16, ts time.Time) {
	lines := bytes.Split([]byte(payload), []byte("\r\n"))
	if len(lines) == 0 {
		return
	}

	requestLine := string(lines[0]) // e.g., GET / HTTP/1.1
	host := ""
	for _, line := range lines {
		if bytes.HasPrefix(line, []byte("Host: ")) {
			host = string(bytes.TrimSpace(bytes.TrimPrefix(line, []byte("Host: "))))
			break
		}
	}

	if host == "" {
		return
	}

	url := extractFullURL(requestLine, host)
	key := hashFlow(srcIP, srcPort, dstIP, dstPort)

	requestMap[key] = HTTPRequest{
		SrcIP:       srcIP,
		SrcPort:     srcPort,
		DstIP:       dstIP,
		DstPort:     dstPort,
		RequestTime: ts,
		URL:         url,
	}
}

// handleResponse matches a 200 OK to a previous GET and tracks the connection
func handleResponse(payload, srcIP string, srcPort uint16, dstIP string, dstPort uint16, ts time.Time) {
	key := hashFlow(dstIP, dstPort, srcIP, srcPort)

	req, ok := requestMap[key]
	if !ok {
		fmt.Printf("Request not found for source IP: %s:%d\n", srcIP, srcPort)
		return
	}

	// Remove the request regardless of response result
	delete(requestMap, key)

	// Only proceed if it's a successful response
	if !strings.Contains(payload, "200 OK") {
		return
	}

	respTime := ts.Sub(req.RequestTime)
	urlHash := hashString(req.URL)

	conn := HTTPConnect{
		SrcIP:          req.SrcIP,
		SrcPort:        req.SrcPort,
		DstIP:          req.DstIP,
		DstPort:        req.DstPort,
		ConnectionTime: req.RequestTime,
		ResponseTime:   respTime,
		URL:            req.URL,
	}
	connectionMap[urlHash] = append(connectionMap[urlHash], conn)

	fmt.Printf("%d [%s] %s:%d -> %s:%d | %v | %s\n",
		connection_cnt, conn.ConnectionTime.Format(time.RFC3339),
		conn.SrcIP, conn.SrcPort, conn.DstIP, conn.DstPort,
		conn.ResponseTime, conn.URL)

	aggregateConnections(conn, urlHash)
	connection_cnt++
}

func extractFullURL(requestLine, host string) string {
	parts := strings.Split(requestLine, " ")
	if len(parts) < 2 {
		return ""
	}
	path := parts[1]
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return "http://" + host + path
}

func hashFlow(srcIP string, srcPort uint16, dstIP string, dstPort uint16) uint64 {
	data := fmt.Sprintf("%s:%d->%s:%d", srcIP, srcPort, dstIP, dstPort)
	h := fnv.New64a()
	h.Write([]byte(data))
	return h.Sum64()
}

func hashString(s string) uint64 {
	h := fnv.New64a()
	h.Write([]byte(s))
	return h.Sum64()
}

// printAggregateList formats and prints all aggregation data in a table
func printAggregateList() {
	fmt.Println("\nAggregated Connections by URL:")
	fmt.Printf("%-20s | %-40s | %-15s | %s\n", "Timestamp", "URL", "Connections No.", "Average Response Time")
	fmt.Println(strings.Repeat("-", 105))

	var lastTS string
	for _, aggr := range aggregateList {
		tsStr := aggr.intervalStartTS.Format("2006-01-02 15:04")

		if tsStr != lastTS {
			lastTS = tsStr
			fmt.Printf("%-20s | %-40s | %-15s | %s\n", tsStr, "", "", "")
		}

		fmt.Printf("%-20s | %-40s | %-15d | %v\n",
			"", aggr.URL, aggr.numOfConns, aggr.avgResponse)
	}
}
