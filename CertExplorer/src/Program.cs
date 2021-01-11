using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace CertExplorer
{
    class Program
    {
        static void Main(string[] args)
        {
            X509FindType x509FindType;

            if ((args.Length < 2)
                || !args[0].Equals("-find")
                || String.IsNullOrWhiteSpace(args[1]))
                throw new ArgumentException("usage: CertExplorer -find {x509FindValue}");

            var certs = CertExplorer.FindMatchingCertificates(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindByThumbprint, args[1], String.Empty, doTakeMostRecentOnly: true);
            List<string> issuers = new List<string> {
                "1b45ec255e0668375043ed5fe78a09ff1655844d",
                "d7fe717b5ff3593764f4d90654d86e8362ec26c8",
                "3ac7c3cac8de0dd392c02789c8be97474f456960",
                "96ea05926e2e42cc207e358668be2c316857fb5e" };
            foreach (var cert in certs)
            {
                var isValid = CertExplorer.TryValidateX509Certificate(cert, issuers);
            }

            //CertExplorer.SetAccessRuleForMatchingCertificates(
            //    StoreLocation.LocalMachine,
            //    StoreName.My,
            //    X509FindType.FindBySubjectName,
            //    "WinFabric-Test-SAN1-Alice",
            //    //"NC encryption cert",
            //    "NT AUTHORITY\\NETWORK SERVICE",
            //    CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead);
            
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
