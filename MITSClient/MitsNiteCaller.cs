using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace MITSClient
{
    internal class MitsNiteCaller
    {
        public MitsNiteCaller(string certTP)
        {
            // find cert by TP in LM\My cert store
            X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine, OpenFlags.OpenExistingOnly);
            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                var certs = store.Certificates.Find(X509FindType.FindByThumbprint, certTP, validOnly: false);
                if (certs.Count == 0)
                    throw new Exception(String.Format("Not a valid SF test configuration: no certificates found matching TP '{0}'.", certTP));

                var handler = new HttpClientHandler()
                {
                    ClientCertificateOptions = ClientCertificateOption.Manual,
                    ServerCertificateCustomValidationCallback = RemoteServerCertificateValidatorCallback
                };
                handler.ClientCertificates.AddRange(certs);

                client_ = new HttpClient(handler)
                {
                    BaseAddress = new Uri("https://localhost:2378")
                };

            }
            catch (CryptographicException ce)
            {
                Console.WriteLine("caught crypto exception {0}: '{1}'", ce.HResult, ce.Message);
            }
            finally
            {
                store.Close();
            }
        }

        private static bool RemoteServerCertificateValidatorCallback(HttpRequestMessage message, X509Certificate2 serverCert, X509Chain serverCertChain, SslPolicyErrors sslPolicyErrors)
        {
            Console.WriteLine("server cert lgtm");
            return true;
        }

        public void MakeTheCall()
        {
            var request = new HttpRequestMessage()
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri("https://localhost:2378/metadata/identity/systoken?api-version=2019-07-01-preview")
            };
            client_.SendAsync(request).Wait();
        }

        private readonly HttpClient client_;
    }
}
