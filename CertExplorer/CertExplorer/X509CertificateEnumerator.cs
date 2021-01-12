using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertExplorer
{
    public static class X509CertificateEnumerator
    {
        public static readonly string LinuxCertStorePath = "/var/lib/sfcerts/";

        private static readonly HashSet<string> CertExtensions = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
            {
                ".cer",
                ".pfx",
                ".pem",
                ".key",
                ".crt",
                ".p12",
            };

        public static List<Tuple<string, string>> List()
        {
            var certX5Ts = new List<Tuple<string, string>>();
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser, OpenFlags.IncludeArchived | OpenFlags.MaxAllowed | OpenFlags.OpenExistingOnly))
            {
                foreach (var cert in store.Certificates)
                {
                    certX5Ts.Add(new Tuple<string, string>(cert.Thumbprint, cert.Subject));
                }
            }

            return certX5Ts;
        }

        public static X509Certificate2Collection Enumerate(StoreLocation location, string name)
        {
#if NETCORE31
            return EnumerateFromDirectory(LinuxCertStorePath);
#else
            return EnumerateFromStore(location, name);
#endif
        }

        private static X509Certificate2Collection EnumerateFromStore(StoreLocation location, string name)
        {
            X509Store store = null;
            X509Certificate2Collection result = new X509Certificate2Collection();

            try
            {
#if NET46
                using store = new X509Store(name, location);
#else
                store = new X509Store(name, location);
#endif
                store.Open(OpenFlags.ReadOnly | OpenFlags.ReadOnly);
                foreach (var cert in store.Certificates)
                {
                    result.Add(new X509Certificate2(cert));
                }
            }
            finally 
            {
#if NET46
                store?.Dispose();
#else
                store?.Close();
#endif
            }

            return result;
        }

        private static X509Certificate2Collection EnumerateFromDirectory(string path)
        {
            X509Certificate2Collection certs = new X509Certificate2Collection();

            Console.WriteLine($"collecting certificates from '{path}'");
            var fileMap = CollectCertificateFiles(path);
            foreach (var entry in fileMap)
            {
                X509Certificate2 cert;
                Console.WriteLine($"\nattempting to build X509Certificate2 object for entry '{entry.Key}'; {entry.Value.Count} files.");
                if (TryCreateX509CertificateFromFiles(entry.Value, out cert))
                {
                    Console.WriteLine($"\tsuccessfully created certificate for entry '{entry.Key}'");
                    certs.Add(cert);
                }
                else
                {
                    Console.WriteLine($"\tSkipping entry {entry.Key}..");
                }
            }

            return certs;
        }

        public static void ListFromDirectory(string path)
        {
            var certs = EnumerateFromDirectory(path);
            foreach (var cert in certs)
            {
                Console.WriteLine("==============");
                Console.WriteLine($"\t\tCN={cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false)}");
                Console.WriteLine($"\t\tTP={cert.Thumbprint}");
                Console.WriteLine($"\t\tHasPrivateKey={cert.HasPrivateKey}");
            }
        }

        private static Dictionary<string, List<string>> CollectCertificateFiles(string path)
        {
            var certFileCatalog = new Dictionary<string, List<string>>(StringComparer.InvariantCultureIgnoreCase);
            var fileNames = Directory.EnumerateFiles(path);

            // traverse list of files, cataloguing the certs by file name
            foreach (var filePath in fileNames)
            {
                Console.WriteLine($"examining enumerated file '{filePath}'");
                var ext = Path.GetExtension(filePath);
                if (!CertExtensions.Contains(ext))
                    continue;

                var name = Path.GetFileNameWithoutExtension(filePath);

                if (!certFileCatalog.ContainsKey(name))
                {
                    Console.WriteLine($"\tnew entry: '{name}'; extension: '{ext}'");
                    var fileList = new List<string> { filePath };
                    certFileCatalog[name] = fileList;
                }
                else
                {
                    // we can safely assume the file list contains no duplicates
                    Console.WriteLine($"\tpossibly-related file: '{filePath}'");
                    certFileCatalog[name].Add(filePath);
                }
            }

            return certFileCatalog;
        }

        private static bool TryCreateX509CertificateFromFiles(List<string> probableCertFiles, out X509Certificate2 certificate)
        {
            bool result = false;
            certificate = null;

            try
            {
                Console.WriteLine($"\tprobable cert file: {probableCertFiles[0]}");
                certificate = X509CertificateBuilder.FromFileList(probableCertFiles);

                result = true;
            }
            catch (CryptographicException ce)
            {
                Console.WriteLine($"Encountered crypto exception: {ce.Message}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"Encountered exception: {e.Message}");
            }

            return result;
        }

    }
}
