using System.Net;

namespace NetworkSniffer.Headers
{
    internal sealed class DNSHeader
    {
        //DNS header fields
        private readonly ushort _identification;        //Sixteen bits for identification
        private readonly ushort _flags;                 //Sixteen bits for DNS flags
        private readonly ushort _totalQuestions;        //Sixteen bits indicating the number of entries 
                                                        //in the questions list
        private readonly ushort _totalAnswerRRs;        //Sixteen bits indicating the number of entries
                                                        //entries in the answer resource record list
        private readonly ushort _totalAuthorityRRs;     //Sixteen bits indicating the number of entries
                                                        //entries in the authority resource record list
        private readonly ushort _totalAdditionalRRs;    //Sixteen bits indicating the number of entries
                                                        //entries in the additional resource record list
                                                        //End DNS header fields

        public string Identification => string.Format("0x{0:x2}", _identification);
        public string Flags => string.Format("0x{0:x2}", _flags);
        public string TotalQuestions => _totalQuestions.ToString();
        public string TotalAnswerRRs => _totalAnswerRRs.ToString();
        public string TotalAuthorityRRs => _totalAuthorityRRs.ToString();
        public string TotalAdditionalRRs => _totalAdditionalRRs.ToString();

        public DNSHeader(byte[] byBuffer, int nReceived)
        {
            MemoryStream memoryStream = new(byBuffer, 0, nReceived);
            BinaryReader binaryReader = new(memoryStream);

            //First sixteen bits are for identification
            _identification = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Next sixteen contain the flags
            _flags = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Read the total numbers of questions in the quesion list
            _totalQuestions = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Read the total number of answers in the answer list
            _totalAnswerRRs = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Read the total number of entries in the authority list
            _totalAuthorityRRs = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

            //Total number of entries in the additional resource record list
            _totalAdditionalRRs = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());
        }
    }
}
