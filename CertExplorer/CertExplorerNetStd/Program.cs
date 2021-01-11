using System;
using System.Collections;
using System.Security.AccessControl;
using System.Security.Cryptography.X509Certificates;

namespace CertExplorerNetStd
{
    class Program
    {
        static void Main(string[] args)
        {
            //if ((args.Length < 2)
            //    || !args[0].Equals("-find")
            //    || String.IsNullOrWhiteSpace(args[1]))
            //    throw new ArgumentException("usage: CertExplorer -find {x509FindValue}");

            CertExplorer.SetAccessRuleForMatchingCertificates(
                StoreLocation.LocalMachine,
                StoreName.My,
                X509FindType.FindBySubjectName,
                "WinFabric-Test-SAN1-Alice",
                //"NC encryption cert",
                "NT AUTHORITY\\NETWORK SERVICE",
                CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead);

            //CertExplorer.TestCertificateRetrieval();
            //CertExplorer.FindMatchingCertificates(StoreName.My, StoreLocation.CurrentUser, args[1]);
            //ListEnvVars();

            //var certList = CertExplorer.ListCertificates();
            //foreach(var certTp in certList)
            //{
            //    Console.WriteLine("* {0}", certTp);
            //}

            //CertExplorer.DumpCertificateProperties("B90A554DD29AD2F6DA3F5ADFB367738053F984C3");
            //CertExplorer.DumpCertificateProperties("C2A92DD7764004BC906B87974F4186E5F9064112");

            return;
        }

        private static void ListEnvVars()
        {
            Console.WriteLine("\n\n====== env vars ==============");
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            {
                Console.WriteLine("  {0} = {1}", entry.Key, entry.Value);
            }
        }
    }
}
