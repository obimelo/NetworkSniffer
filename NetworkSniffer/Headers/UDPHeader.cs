using System.Net;

namespace NetworkSniffer.Headers
{
    internal sealed class UDPHeader
    {
        //UDP header fields
        private readonly ushort _sourcePort;                    //Sixteen bits for the source port number        
        private readonly ushort _destinationPort;               //Sixteen bits for the destination port number
        private readonly ushort _length;                        //Length of the UDP header
        private readonly short _checksum;                       //Sixteen bits for the checksum
                                                                //(checksum can be negative so taken as short)              
                                                                //End UDP header fields

        private readonly byte[] _udpData = Array.Empty<byte>();     //Data carried by the UDP packet

        public UDPHeader(byte[] byBuffer, int nReceived)
        {
            MemoryStream memoryStream = new(byBuffer, 0, nReceived);
            BinaryReader binaryReader = new(memoryStream);

            //The first sixteen bits contain the source port
            _sourcePort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //The next sixteen bits contain the destination port
            _destinationPort = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //The next sixteen bits contain the length of the UDP packet
            _length = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //The next sixteen bits contain the checksum
            _checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Copy the data carried by the UDP packet into the data buffer
            _udpData = new byte[nReceived - 8];

            Buffer.BlockCopy
                (
                    byBuffer,
                    8,               //The UDP header is of 8 bytes so we start copying after it
                    _udpData,
                    0,
                    nReceived - 8
                );
        }

        public string SourcePort => _sourcePort.ToString();

        public string DestinationPort => _destinationPort.ToString();

        public string Length => _length.ToString();

        //Return the checksum in hexadecimal format
        public string Checksum => string.Format("0x{0:x2}", _checksum);

        public byte[] Data => _udpData;
    }
}
