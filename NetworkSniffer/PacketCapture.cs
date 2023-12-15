using NetworkSniffer.Enums;
using NetworkSniffer.Headers;
using NetworkSniffer.Helpers;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace NetworkSniffer
{
    internal class PacketCapture : IDisposable
    {
        private readonly string _hostIpAddress;
        private short _maxCapturingPackets = 0;
        private readonly string? _filterIpAddress;
        private Socket _mainSocket = null!;                     // The socket which captures all incoming packets
        private byte[] _byteData = new byte[65544];
        private short _capturingCount = 0;

        public PacketCapture(short maxCapturingPackets, string? filterIpAddress = null)
        {
            _hostIpAddress = "10.50.111.112";
            _maxCapturingPackets |= maxCapturingPackets;
            _filterIpAddress = filterIpAddress;

            //IPHostEntry HosyEntry = Dns.GetHostEntry((Dns.GetHostName()));

            //if (HosyEntry.AddressList.Length > 0)
            //{
            //    foreach (IPAddress ip in HosyEntry.AddressList)
            //    {
            //        strIP = ip.ToString();
            //        //cmbInterfaces.Items.Add(strIP);
            //    }
            //}
        }

        public void Dispose()
        {
            if (_mainSocket != null) 
                _mainSocket.Close();
        }

        public bool KeepCapturing() => _capturingCount < _maxCapturingPackets;

        public void StartCapturing(bool onlyTcpPushPackets = false)
        {
            // For sniffing the socket to capture the packets has to be a raw socket, with the
            // address family being of type internetwork, and protocol being IP
            _mainSocket = new(AddressFamily.InterNetwork, SocketType.Raw, ProtocolType.IP);

            try
            {
                // Bind the socket to the selected IP address
                _mainSocket.Bind(new IPEndPoint(IPAddress.Parse(_hostIpAddress), 0));

                // Set the socket  options
                _mainSocket.SetSocketOption(SocketOptionLevel.IP,               //Applies only to IP packets
                                            SocketOptionName.HeaderIncluded,    //Set the include the header
                                            true);                              //option to true

                byte[] byTrue = new byte[4] { 1, 0, 0, 0 };
                byte[] byOut = new byte[4] { 1, 0, 0, 0 };                      //Capture outgoing packets

                // Socket.IOControl is analogous to the WSAIoctl method of Winsock 2
                _mainSocket.IOControl(IOControlCode.ReceiveAll,                 //Equivalent to SIO_RCVALL constant of Winsock 2
                                     byTrue,
                                     byOut);

                // Start receiving the packets asynchronously
                _capturingCount = 0;

                while (KeepCapturing())
                {
                    _byteData = new byte[65544];

                    int nReceived = _mainSocket.Receive(_byteData, 0, _byteData.Length, SocketFlags.None);

                    //Since all protocol packets are encapsulated in the IP datagram
                    //so we start by parsing the IP header and see what protocol data
                    //is being carried by it
                    IPHeader ipHeader = new(_byteData, nReceived);

                    // Check Filter Address
                    if (_filterIpAddress != null && _filterIpAddress != ipHeader.SourceAddress.ToString() && _filterIpAddress != ipHeader.DestinationAddress.ToString())
                        continue;

                    // Analyze the bytes received...

                    ParseData(ipHeader, _capturingCount, onlyTcpPushPackets);

                    _capturingCount++;
                }
            }
            finally
            {
                _mainSocket.Close();
            }
        }

        private static void ParseData(IPHeader ipHeader, short capturingCount, bool onlyTcpPushPackets = false)
        {
            TreeNode rootNode = new($"Capturing {capturingCount} : {ipHeader.SourceAddress} => {ipHeader.DestinationAddress}");

            TreeNode ipNode = MakeIPTreeNode(ipHeader);
            rootNode.Nodes.Add(ipNode);

            //Now according to the protocol being carried by the IP datagram we parse 
            //the data field of the datagram
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:

                    TCPHeader tcpHeader = new(ipHeader.Data,                //IPHeader.Data stores the data being carried by the IP datagram
                                              ipHeader.MessageLength);      //Length of the data field                    

                    if (onlyTcpPushPackets && !tcpHeader.IsPushPacket)
                        return;

                    TreeNode tcpNode = MakeTCPTreeNode(tcpHeader);

                    rootNode.Nodes.Add(tcpNode);

                    // If the port is equal to 53 then the underlying protocol is DNS
                    // Note: DNS can use either TCP or UDP thats why the check is done twice
                    if (tcpHeader.DestinationPort == "53" || tcpHeader.SourcePort == "53")
                    {
                        TreeNode dnsNode = MakeDNSTreeNode(tcpHeader.HeaderData, (int)tcpHeader.MessageLength);
                        rootNode.Nodes.Add(dnsNode);
                    }

                    break;

                case Protocol.UDP:

                    UDPHeader udpHeader = new(ipHeader.Data,                //IPHeader.Data stores the data being carried by the IP datagram
                                              (int)ipHeader.MessageLength); //Length of the data field                    

                    TreeNode udpNode = MakeUDPTreeNode(udpHeader);

                    rootNode.Nodes.Add(udpNode);

                    //If the port is equal to 53 then the underlying protocol is DNS
                    //Note: DNS can use either TCP or UDP thats why the check is done twice
                    if (udpHeader.DestinationPort == "53" || udpHeader.SourcePort == "53")
                    {
                        TreeNode dnsNode = MakeDNSTreeNode(udpHeader.Data,
                                                           //Length of UDP header is always eight bytes so we subtract that out of the total 
                                                           //length to find the length of the data
                                                           Convert.ToInt32(udpHeader.Length) - 8);
                        rootNode.Nodes.Add(dnsNode);
                    }

                    break;

                case Protocol.Unknown:
                    break;
            }

            rootNode.Print();
        }

        // Helper function which returns the information contained in the IP header as a tree node
        private static TreeNode MakeIPTreeNode(IPHeader ipHeader)
        {
            TreeNode ipNode = new("IP");

            ipNode.Nodes.Add("Ver: " + ipHeader.Version);
            ipNode.Nodes.Add("Header Length: " + ipHeader.HeaderLength);
            ipNode.Nodes.Add("Differentiated Services: " + ipHeader.DifferentiatedServices);
            ipNode.Nodes.Add("Total Length: " + ipHeader.TotalLength);
            ipNode.Nodes.Add("Identification: " + ipHeader.Identification);
            ipNode.Nodes.Add("Flags: " + ipHeader.Flags);
            ipNode.Nodes.Add("Fragmentation Offset: " + ipHeader.FragmentationOffset);
            ipNode.Nodes.Add("Time to live: " + ipHeader.TTL);
            switch (ipHeader.ProtocolType)
            {
                case Protocol.TCP:
                    ipNode.Nodes.Add("Protocol: " + "TCP");
                    break;
                case Protocol.UDP:
                    ipNode.Nodes.Add("Protocol: " + "UDP");
                    break;
                case Protocol.Unknown:
                    ipNode.Nodes.Add("Protocol: " + "Unknown");
                    break;
            }
            ipNode.Nodes.Add("Checksum: " + ipHeader.Checksum);
            ipNode.Nodes.Add("Source: " + ipHeader.SourceAddress.ToString());
            ipNode.Nodes.Add("Destination: " + ipHeader.DestinationAddress.ToString());

            return ipNode;
        }

        // Helper function which returns the information contained in the TCP header as a tree node
        private static TreeNode MakeTCPTreeNode(TCPHeader tcpHeader)
        {
            TreeNode tcpNode = new("TCP");

            tcpNode.Nodes.Add("Source Port: " + tcpHeader.SourcePort);
            tcpNode.Nodes.Add("Destination Port: " + tcpHeader.DestinationPort);
            tcpNode.Nodes.Add("Sequence Number: " + tcpHeader.SequenceNumber);

            if (tcpHeader.AcknowledgementNumber != "")
                tcpNode.Nodes.Add("Acknowledgement Number: " + tcpHeader.AcknowledgementNumber);

            tcpNode.Nodes.Add("Header Length: " + tcpHeader.HeaderLength);
            tcpNode.Nodes.Add("Flags: " + tcpHeader.Flags);
            tcpNode.Nodes.Add("Window Size: " + tcpHeader.WindowSize);
            tcpNode.Nodes.Add("Checksum: " + tcpHeader.Checksum);

            if (tcpHeader.UrgentPointer != "")
                tcpNode.Nodes.Add("Urgent Pointer: " + tcpHeader.UrgentPointer);

            tcpNode.Nodes.Add("Header Data: " + ByteArrayToString(tcpHeader.HeaderData));
            tcpNode.Nodes.Add("Payload Data: " + ByteArrayToString(tcpHeader.PayloadData));

            return tcpNode;
        }

        // Helper function which returns the information contained in the UDP header as a tree node
        private static TreeNode MakeUDPTreeNode(UDPHeader udpHeader)
        {
            TreeNode udpNode = new("UDP");

            udpNode.Nodes.Add("Source Port: " + udpHeader.SourcePort);
            udpNode.Nodes.Add("Destination Port: " + udpHeader.DestinationPort);
            udpNode.Nodes.Add("Length: " + udpHeader.Length);
            udpNode.Nodes.Add("Checksum: " + udpHeader.Checksum);
            udpNode.Nodes.Add("Data: " + ByteArrayToString(udpHeader.Data));

            return udpNode;
        }

        // Helper function which returns the information contained in the DNS header as a tree node
        private static TreeNode MakeDNSTreeNode(byte[] byteData, int nLength)
        {
            DNSHeader dnsHeader = new(byteData, nLength);

            TreeNode dnsNode = new("DNS");

            dnsNode.Nodes.Add("Identification: " + dnsHeader.Identification);
            dnsNode.Nodes.Add("Flags: " + dnsHeader.Flags);
            dnsNode.Nodes.Add("Questions: " + dnsHeader.TotalQuestions);
            dnsNode.Nodes.Add("Answer RRs: " + dnsHeader.TotalAnswerRRs);
            dnsNode.Nodes.Add("Authority RRs: " + dnsHeader.TotalAuthorityRRs);
            dnsNode.Nodes.Add("Additional RRs: " + dnsHeader.TotalAdditionalRRs);

            return dnsNode;
        }

        private static string ByteArrayToString(byte[] ba)
        {
            StringBuilder hex = new(ba.Length * 2);
            foreach (byte b in ba)
                hex.AppendFormat("{0:x2}", b);
            return hex.ToString();
        }
    }
}
