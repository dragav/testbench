using Microsoft.Rest;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Data;
using System.Net.Http;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertExplorer
{
    internal class AutoIssuers : IDisposable
    {
        private bool disposed = false;
        private static readonly HttpClient httpClient_;
        private readonly string getIssuersUri = "https://issuer.pki.azure.com/dsms/issuercertificates?getissuersv2&appType=ssl";
        Logger logger_;

        static AutoIssuers()
        {
            httpClient_ = new HttpClient();
        }

        public AutoIssuers(string issuerUri, Logger logger)
        {
            if (!String.IsNullOrWhiteSpace(issuerUri)) 
            { 
                getIssuersUri = issuerUri;
            }
            this.logger_ = logger;
            httpClient_.BaseAddress = new Uri(getIssuersUri);
        }

        public void Run()
        {
            if (!TryGetIssuersFromEndpoint(getIssuersUri, out var issuers))
                throw new Exception("foff");

            PrintIssuerTree(issuers);

            var issuerMap = FindCrossSignedIssuers(issuers);
            PrintCrossSignedIssuerMap(issuerMap, skipSingles: true);
        }

        public bool TryGetIssuersFromEndpoint(string issuerUri, out IssuerCertificatesTree issuerTree)
        {
            issuerTree = null;
            try
            {
                var response = httpClient_.GetAsync(issuerUri)
                    .ConfigureAwait(false)
                    .GetAwaiter()
                    .GetResult();

                if (!response.IsSuccessStatusCode)
                {
                    logger_.Log(LogLevel.Info, String.Format($"failed to read issuers from '{issuerUri}'; error: {response.StatusCode}: {response.ReasonPhrase}"));
                    return false;
                }

                string responseStr = response.Content
                    .ReadAsStringAsync()
                    .ConfigureAwait(false)
                    .GetAwaiter()
                    .GetResult();

                issuerTree = JsonConvert.DeserializeObject<IssuerCertificatesTree>(responseStr);
                if (issuerTree == null
                    || issuerTree.RootsInfos.Count < 1)
                {
                    logger_.Log(LogLevel.Info, "GetIssuers call returned an empty issuer tree; please check the parameters of the API call: http://aka.ms/getissuers");
                    return false;
                }
            }
            catch (Exception ex)
            {
                logger_.Log(LogLevel.Info, ex.Message);
                return false;
            }

            return true;
        }

        private static Dictionary<string, List<Tuple<string, string, string, string, string>>> FindCrossSignedIssuers(IssuerCertificatesTree issuerTree)
        {
            var map = new Dictionary<string, List<Tuple<string, string, string, string, string>>>();
            foreach (var root in issuerTree.RootsInfos)
            {
                var rootName = root.CaName;
                foreach (var ca in root.Intermediates)
                {
                    var ski = GetSubjectKeyIdentifier(ca.Certificate);
                    var tp = Sha1ThumbprintFromIssuerName(ca.IntermediateName);
                    if (!map.ContainsKey(ski))
                    {
                        map[ski] = new List<Tuple<string, string, string, string, string>>();
                    }
                    map[ski].Add(new Tuple<string, string, string, string, string>(
                        ca.Certificate.GetNameInfo(X509NameType.SimpleName, false),
                        tp,
                        ca.Certificate.NotBefore.ToShortDateString(),
                        ca.Certificate.NotAfter.ToShortDateString(),
                        rootName));
                }
            }

            return map;
        }

        private static void PrintCrossSignedIssuerMap(Dictionary<string, List<Tuple<string, string, string, string, string>>> issuerMap, bool skipSingles)
        {
            foreach (var entry in issuerMap)
            {
                if (skipSingles && entry.Value.Count < 2)
                {
                    continue;
                }

                Console.WriteLine($"{entry.Key}:{entry.Value.Count}");
                foreach (var kvp in entry.Value)
                {
                    Console.WriteLine($"\t{kvp.Item1}, TP:{kvp.Item2}, NBF:{kvp.Item3}, NA:{kvp.Item4}, by {kvp.Item5}");
                }
            }
        }

        private void PrintIssuerTree(IssuerCertificatesTree issuerTree)
        {
            foreach (var rootInfo in issuerTree.RootsInfos)
            {
                logger_.Log(LogLevel.Info, String.Format($"processing CAs of {rootInfo.CaName}"));
                PrintRootInfo(rootInfo);
                Console.WriteLine("=================");
            }
        }

        public static string[] GetIssuerTPs(IssuerCertificatesTree issuerTree)
        {
            List<string> issuerTps = new List<string>(10);
            foreach (var rootInfo in issuerTree.RootsInfos)
            {
                foreach (var issuerInfo in rootInfo.Intermediates)
                {
                    issuerTps.Add(Sha1ThumbprintFromIssuerName(issuerInfo.IntermediateName));
                }
            }

            return issuerTps.ToArray();
        }

        private static void PrintRootInfo(RootCertInfo rootInfo)
        {
            var issuerTp = Sha1ThumbprintFromIssuerName(rootInfo.RootName);
            var data = PrintCertData(rootInfo.Certificate);

            Console.WriteLine($"{rootInfo.CaName} w/ TP: {issuerTp}, {data}; {rootInfo.Intermediates.Count} CAs:\n|");
            foreach (var issuer in rootInfo.Intermediates)
            {
                Console.Write("|--");
                PrintIntermediateInfo(issuer);
            }
        }

        private static void PrintIntermediateInfo(IntermediateCertInfo caInfo)
        {
            var issuerTp = Sha1ThumbprintFromIssuerName(caInfo.IntermediateName);
            var data = PrintCertData(caInfo.Certificate);
            var friendlyName = caInfo.Certificate.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            Console.WriteLine($"\t{friendlyName} w/ TP: {issuerTp}, {data}");
        }

        private static string Sha1ThumbprintFromIssuerName(string issuerName)
        {
            // the id is a string of this form: '/certificates/imported/intermediatecertificates/1e981ccddc69102a45c6693ee84389c3cf2329f1', with the trailing element being its SHA-1 thumbprint.
            var issuerTpTokens = issuerName.Split('/', StringSplitOptions.RemoveEmptyEntries);
            return issuerTpTokens[issuerTpTokens.Length - 1];
        }

        private static string GetSubjectKeyIdentifier(X509Certificate2 cert)
        {
            string ski = string.Empty;
            foreach (var ext in cert.Extensions)
            {
                if (ext.Oid.Value == "2.5.29.14")
                {
                    ski = ext.Format(false);
                    break;
                }
            }

            return ski;
        }

        private static string PrintCertData(X509Certificate2 cert)
        {
            return String.Format($"SKI: {GetSubjectKeyIdentifier(cert)}, NBF: {cert.NotBefore.ToShortDateString()}, NA: {cert.NotAfter.ToShortDateString()}");
        }

        #region i dispose of things
        ~AutoIssuers()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    if (httpClient_ != null)
                    {
                        httpClient_.CancelPendingRequests();
                    }
                }

                disposed = true;
            }
        }

        #endregion
    }
}
