using System;

namespace MITSClient
{
    internal class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("Hello World!");

            var caller = new MitsNiteCaller("6EC2F8EBCC2E8A8600DBD7E37F48F45B7613B0E7");
            caller.MakeTheCall();
        }
    }
}
