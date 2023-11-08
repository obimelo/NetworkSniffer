using NetworkSniffer.Enums;
using System.Net;

namespace NetworkSniffer.Headers
{
    internal sealed class IPHeader
    {
        //IP Header fields
        private readonly byte _versionAndHeaderLength;              //Eight bits for version and header length
        private readonly byte _differentiatedServices;              //Eight bits for differentiated services (TOS)
        private readonly ushort _totalLength;                       //Sixteen bits for total length of the datagram (header + message)
        private readonly ushort _identification;                    //Sixteen bits for identification
        private readonly ushort _flagsAndOffset;                    //Eight bits for flags and fragmentation offset
        private readonly byte _ttl;                                 //Eight bits for TTL (Time To Live)
        private readonly byte _protocol;                            //Eight bits for the underlying protocol
        private readonly short _checksum;                           //Sixteen bits containing the checksum of the header
                                                                    //(checksum can be negative so taken as short)
        private readonly uint _sourceIPAddress;                     //Thirty two bit source IP Address
        private readonly uint _destinationIPAddress;                //Thirty two bit destination IP Address
                                                                    //End IP Header fields

        private readonly byte _headerLength;                        //Header length
        private readonly byte[] _ipData = Array.Empty<byte>();      //Data carried by the datagram

        public IPHeader(byte[] byBuffer, int nReceived)
        {
            try
            {
                //Create MemoryStream out of the received bytes
                MemoryStream memoryStream = new(byBuffer, 0, nReceived);

                //Next we create a BinaryReader out of the MemoryStream
                BinaryReader binaryReader = new(memoryStream);

                //The first eight bits of the IP header contain the version and
                //header length so we read them
                _versionAndHeaderLength = binaryReader.ReadByte();

                //The next eight bits contain the Differentiated services
                _differentiatedServices = binaryReader.ReadByte();

                //Next eight bits hold the total length of the datagram
                _totalLength = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                //Next sixteen have the identification bytes
                _identification = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                //Next sixteen bits contain the flags and fragmentation offset
                _flagsAndOffset = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                //Next eight bits have the TTL value
                _ttl = binaryReader.ReadByte();

                //Next eight represnts the protocol encapsulated in the datagram
                _protocol = binaryReader.ReadByte();

                //Next sixteen bits contain the checksum of the header
                _checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                //Next thirty two bits have the source IP address
                _sourceIPAddress = (uint)binaryReader.ReadInt32();

                //Next thirty two hold the destination IP address
                _destinationIPAddress = (uint)binaryReader.ReadInt32();

                //Now we calculate the header length

                _headerLength = _versionAndHeaderLength;
                //The last four bits of the version and header length field contain the
                //header length, we perform some simple binary airthmatic operations to
                //extract them
                _headerLength <<= 4;
                _headerLength >>= 4;
                //Multiply by four to get the exact header length
                _headerLength *= 4;

                //Copy the data carried by the data gram into another array so that
                //according to the protocol being carried in the IP datagram
                _ipData = new byte[_totalLength - _headerLength];

                Buffer.BlockCopy
                    (
                        byBuffer,
                        _headerLength,  //start copying from the end of the header
                        _ipData, 0,
                        _totalLength - _headerLength
                    );
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }

        public string Version
        {
            get
            {
                //Calculate the IP version

                //The four bits of the IP header contain the IP version
                if (_versionAndHeaderLength >> 4 == 4)
                {
                    return "IP v4";
                }
                else if (_versionAndHeaderLength >> 4 == 6)
                {
                    return "IP v6";
                }
                else
                {
                    return "Unknown";
                }
            }
        }

        public string HeaderLength => _headerLength.ToString();

        //MessageLength = Total length of the datagram - Header length
        public ushort MessageLength => (ushort)(_totalLength - _headerLength);

        //Returns the differentiated services in hexadecimal format
        public string DifferentiatedServices => string.Format("0x{0:x2} ({1})", _differentiatedServices, _differentiatedServices);

        public string Flags
        {
            get
            {
                //The first three bits of the flags and fragmentation field 
                //represent the flags (which indicate whether the data is 
                //fragmented or not)
                int nFlags = _flagsAndOffset >> 13;
                if (nFlags == 2)
                {
                    return "Don't fragment";
                }
                else if (nFlags == 1)
                {
                    return "More fragments to come";
                }
                else
                {
                    return nFlags.ToString();
                }
            }
        }

        public string FragmentationOffset
        {
            get
            {
                //The last thirteen bits of the flags and fragmentation field 
                //contain the fragmentation offset
                int nOffset = _flagsAndOffset << 3;
                nOffset >>= 3;

                return nOffset.ToString();
            }
        }

        public string TTL => _ttl.ToString();

        public Protocol ProtocolType
        {
            get
            {
                //The protocol field represents the protocol in the data portion
                //of the datagram
                if (_protocol == 6)        //A value of six represents the TCP protocol
                {
                    return Protocol.TCP;
                }
                else if (_protocol == 17)  //Seventeen for UDP
                {
                    return Protocol.UDP;
                }
                else
                {
                    return Protocol.Unknown;
                }
            }
        }

        //Returns the checksum in hexadecimal format
        public string Checksum => string.Format("0x{0:x2}", _checksum);

        public IPAddress SourceAddress => new(_sourceIPAddress);

        public IPAddress DestinationAddress => new(_destinationIPAddress);

        public string TotalLength => _totalLength.ToString();

        public string Identification => _identification.ToString();

        public byte[] Data => _ipData;
    }
}
