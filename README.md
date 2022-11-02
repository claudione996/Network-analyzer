# Network-analyzer
The project aims at building a multiplatform application capable of intercepting incoming
and outgoing traffic through the network interfaces of a computer. The application will set
the network adapter in promiscuous mode, collect IP address, port and protocol type of
observed traffic and will generate a textual report describing a synthesis of the observed
events.
Such a report should list for each of the network address/port pairs that have been
observed, the protocols that was transported, the cumulated number of bytes transmitted,
the timestamp of the first and last occurrence of information exchange.
Command line parameters will be used to specify the network adapter to be inspected, the
output file to be generated, the interval after which a new report is to be generated, or a
possible filter to apply to captured data.
