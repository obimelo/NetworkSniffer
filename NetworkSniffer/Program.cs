namespace NetworkSniffer
{
    internal class Program
    {
        static void Main(string[] args)
        {
            using (PacketCapture pc = new(50, "10.50.111.136"))
            {
                pc.StartCapturing(false);
            }

            Console.WriteLine("FINISH");
        }
    }
}
