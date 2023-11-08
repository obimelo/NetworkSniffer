namespace NetworkSniffer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            using (PacketCapture pc = new(50, "192.168.39.16"))
            {
                pc.StartCapturing(true);
            }

            Console.WriteLine("FINISH");
        }
    }
}
