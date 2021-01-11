using System;
using System.Collections.Generic;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CertExplorer
{
    public sealed class CertExplorer
    {
        private static readonly string StoreNamePersonal = "My";
        private static readonly string StoreLocationLM = "LocalMachine";
        private static readonly string CNPrefix = "WinFabric-Test-";

        private static readonly OpenFlags openFlags = OpenFlags.IncludeArchived | OpenFlags.MaxAllowed | OpenFlags.OpenExistingOnly;
        public static List<Tuple<string, string>> ListCertificates()
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

        private delegate bool IsCertificateAMatchForFindValue(X509Certificate2 enumeratedCert, string findValue);

        private static bool IsMatchByThumbprint(X509Certificate2 enumeratedCert, string x509FindValue)
        {
            return StringComparer.OrdinalIgnoreCase.Equals(x509FindValue, enumeratedCert.Thumbprint);
        }

        private static bool IsMatchBySubjectCommonName(X509Certificate2 enumeratedCert, string x509FindValue)
        {
            /// the find value, if used with X509FindType.FindBySubject, yields erroneous matches: mismatching casing, or certificates
            /// whose subject is a superstring of the one we're looking for. FindByDistinguishedName fails as well - .net does not seem
            /// to support finding a cert by its own DN. At the recommendation of the CLR team, the best option is to do an exact match 
            /// of the find value with a certificate's SimpleName, which is the 'name' value calculated by a definitely-not-simple algorithm.
            /// We're relaxing the exact match to a case-insensitive one; this isn't what the runtime is doing, but the intent here is 
            /// to find/compare DNS-type names. 
            return StringComparer.OrdinalIgnoreCase.Equals(x509FindValue, enumeratedCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false));
        }

        public static X509Certificate2Collection FindMatchingCertificates(
            string storeLocationStr,
            string storeNameStr,
            string findTypeStr,
            string findValue,
            string secondaryFindValue,
            bool doTakeMostRecentOnly)
        {
            if (!Enum.TryParse(storeLocationStr, out StoreLocation storeLocation))
            {
                throw new ArgumentException("X509FindType in cluster manifest is not of proper enum value");
            }

            if (!Enum.TryParse(findTypeStr, out X509FindType findType))
            {
                throw new ArgumentException("X509FindType in cluster manifest is not of proper enum value");
            }

            return FindMatchingCertificates(storeLocation, storeNameStr, findType, findValue, secondaryFindValue, doTakeMostRecentOnly);
        }

        public static X509Certificate2Collection FindMatchingCertificates(
            StoreLocation storeLocation,
            StoreName storeName,
            X509FindType findType,
            string findValue,
            string secondaryFindValue,
            bool doTakeMostRecentOnly)
        {
            return FindMatchingCertificates(storeLocation, storeName.ToString(), findType, findValue, secondaryFindValue, doTakeMostRecentOnly);
        }

        public static X509Certificate2Collection FindMatchingCertificates(
            StoreLocation storeLocation,
            string storeName,
            X509FindType findType,
            string findValue,
            string secondaryFindValue,
            bool doTakeMostRecentOnly)
        {
            X509Store store;

            var certificates = new X509Certificate2Collection();
            if (string.IsNullOrWhiteSpace(storeName) ||
                string.IsNullOrWhiteSpace(findValue))
            {
                Console.WriteLine("PaasCoordinator: No certificate configured");

                // Fall back to 'anonymous' self-signed certificate so that WRP's web host
                // does not reject the connection for lacking a cert. This certificate is
                // installed by the ServiceFabric extension when no cluster security is configured.
                // It is not trusted in any way, and only works when cert security is disabled for
                // the cluster resource.

                // CoreCLR Does not support StoreLocation.LocalMachine, hence using StoreLocation.CurrentUser
#if DotNetCoreClrLinux
                store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
#else
                store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
#endif
                try
                {
                    store.Open(OpenFlags.ReadOnly);

                    var certCollections = store.Certificates.Find(
                        X509FindType.FindBySubjectDistinguishedName,
                        "AnonymousCertDistiguishedName",
                        false /*load self-signed cert*/);

                    if (certCollections.Count > 0)
                    {
                        certificates.Add(certCollections[0]);
                    }
                }
                finally
                {
#if DotNetCoreClrLinux
                    store.Dispose();
#else
                    store.Close();
#endif
                }

                return certificates;
            }

            IsCertificateAMatchForFindValue matchCert;
            switch (findType)
            {
                case X509FindType.FindByThumbprint:
                    matchCert = IsMatchByThumbprint;
                    break;

                case X509FindType.FindBySubjectName:
                    matchCert = IsMatchBySubjectCommonName;
                    break;

                default:
                    throw new ArgumentException("Unsupported X509FindType: '{0}'; supported values are FindByThumbprint and FindBySubjectName", findType.ToString());
            }

            // SFRP is generating ClusterManifests setting this value to StoreLocation.LocalMachine
            // Using hard-coded value of StoreLocation.CurrentUser for TP9 till SFRP is updated to set this value appropriately.
#if DotNetCoreClrLinux
            using (store = new X509Store(storeName, StoreLocation.CurrentUser))
#else
            using (store = new X509Store(storeName, storeLocation))
#endif
            {
                X509Certificate2 selectedCert = null;
                try
                {
                    bool excludeExpiredCerts = true;    // todo [dragosav]: update when enabling support for expired certs
                    bool isTimeValidCert = false;
                    bool isExpiredCert = false;
                    bool anyMatchFound = false;
                    DateTime now = DateTime.Now;        // cert validity is presented in local time.

                    store.Open(OpenFlags.ReadOnly);

                    var findValues = new List<string>() { findValue };
                    if (!string.IsNullOrEmpty(secondaryFindValue))
                    {
                        findValues.Add(secondaryFindValue);
                    }

                    foreach (var value in findValues)
                    {
                        Console.WriteLine("Finding matching certificates for find value '{0}'; excludeExpiredCerts = '{1}'", findValue, excludeExpiredCerts);
                        foreach (var enumeratedCert in store.Certificates)
                        {
                            isExpiredCert = DateTime.Compare(now, enumeratedCert.NotAfter) > 0;
                            isTimeValidCert = !(excludeExpiredCerts && isExpiredCert)
                                            && DateTime.Compare(now, enumeratedCert.NotBefore) >= 0;
                            if (matchCert(enumeratedCert, value)
                                && isTimeValidCert)
                            {
                                anyMatchFound = true;

                                Console.WriteLine("Found matching certificate: Thumbprint {0}, NotBefore {1}, NotAfter {2}, Subject {3}",
                                    enumeratedCert.Thumbprint,
                                    enumeratedCert.NotBefore,
                                    enumeratedCert.NotAfter,
                                    enumeratedCert.Subject);

                                if (!doTakeMostRecentOnly)
                                {
                                    // if taking all, add it here and continue
                                    certificates.Add(enumeratedCert);
                                    continue;
                                }

                                // Select the most recent and farthest valid matching cert.
                                // This should make it predictible if certificate is compromised and it needs to be replaced with a newer one.
                                if (selectedCert == null
                                    || selectedCert.NotBefore < enumeratedCert.NotBefore)
                                {
                                    selectedCert = enumeratedCert;
                                }
                                else if (selectedCert.NotBefore == enumeratedCert.NotBefore
                                    && !selectedCert.Thumbprint.Equals(enumeratedCert.Thumbprint))
                                {
                                    // if both were issued at the same time, prefer the farthest valid
                                    selectedCert = selectedCert.NotAfter >= enumeratedCert.NotAfter ? selectedCert : enumeratedCert;
                                }
                            }
                        }
                    }

                    if (selectedCert != null
                        && doTakeMostRecentOnly)
                    {
                        Console.WriteLine("Selected certificate: Thumbprint {0}, NotBefore {1}, NotAfter {2}, Subject {3}",
                            selectedCert.Thumbprint,
                            selectedCert.NotBefore,
                            selectedCert.NotAfter,
                            selectedCert.Subject);

                        certificates.Add(selectedCert);
                    }
                    else
                    {
                        Console.WriteLine("No {0} certificate found: StoreName {1}, StoreLocation {2}, FindType {3}, FindValue {4}",
                            anyMatchFound ? "valid" : "matching",
                            storeName,
                            storeLocation,
                            findType,
                            findValue);
                    }
                }
                finally
                {
#if DotNetCoreClrLinux
                    store.Dispose();
#else
                    store.Close();
#endif
                }
            }

            if (certificates.Count == 0)
            {
                throw new InvalidOperationException("Could not load primary and secondary certificate");
            }

            return certificates;
        }

        private static Dictionary<string, X509Certificate2Collection> InventoryTestCerts(
            X509Certificate2Collection testCerts, 
            out string duplicateCN, 
            out string expiredCN,
            out string expiredTP)
        {
            var certMap = new Dictionary<string, X509Certificate2Collection>();

            duplicateCN = String.Empty;
            expiredCN = String.Empty;
            expiredTP = String.Empty;

            // inventory them, to ensure we have all the expected kinds of certs
            bool haveDuplicateCNs = false;
            bool haveExpiredCerts = false;
            bool isExpiredCert = false;
            bool isTimeValidCert = false;
            bool excludeExpiredCerts = true;
            var now = DateTime.Now;
            foreach (var testCert in testCerts)
            {
                var cn = testCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                Console.WriteLine("enumerated: CN={0}, TP={1}, NBF={2}, NA={3}",
                    cn,
                    testCert.Thumbprint.ToString(),
                    testCert.NotBefore,
                    testCert.NotAfter);

                isExpiredCert = now > testCert.NotAfter;
                isTimeValidCert = !(excludeExpiredCerts && isExpiredCert)
                                && now >= testCert.NotBefore;

                // take the first expired one
                if (!haveExpiredCerts
                    && isExpiredCert)
                {
                    expiredCN = cn;
                    expiredTP = testCert.Thumbprint;
                }
                haveExpiredCerts |= isExpiredCert;

                if (!certMap.ContainsKey(cn))
                {
                    certMap[cn] = new X509Certificate2Collection();
                }
                else
                {
                    if (!haveDuplicateCNs)
                    {
                        duplicateCN = cn;
                    }
                    haveDuplicateCNs = true;
                }

                certMap[cn].Add(testCert);
            }

            Console.WriteLine("inventoried {0} distinct certs; have duplicate names: {1}; have expired certs: {2}", certMap.Count, haveDuplicateCNs, haveExpiredCerts);

            return certMap;
        }

        private static bool VerifyCertsAreEqual(X509Certificate2 lhs, X509Certificate2 rhs)
        {
            return lhs.Thumbprint.Equals(rhs.Thumbprint);
        }

        public static void TestCertificateRetrieval()
        {
            // retrieve the winfab certs with SubjectName matching
            var testCerts = RetrieveTestCerts(StoreNamePersonal, StoreLocationLM, CNPrefix);

            // inventory them to ensure we have certs for all test scenarios
            var testCertCatalog = InventoryTestCerts(testCerts, out string duplicateCN, out string expiredCN, out string expiredTP);

            // start running the tests
            // 1. ensure we get an exact match
            Console.WriteLine("\n** running test case 1");
            // pick a CN which has a single match
            string expectedCN = String.Empty;
            X509Certificate2 expectedCert = null;
            foreach (var kvp in testCertCatalog)
            {
                if (kvp.Value.Count > 1)
                {
                    continue;
                }

                expectedCN = kvp.Key;
                expectedCert = kvp.Value[0];
                break;
            }

            if (String.IsNullOrWhiteSpace(expectedCN))
            {
                // highly unlikely, but all have duplicates
                // pick a cn at random, and pick a non-expired cert with that cn
                var targetIdx = new Random((int)DateTime.UtcNow.Ticks).Next(testCertCatalog.Count - 1);
                var idx = 0; // grr; no index-based access
                foreach (var certKvp in testCertCatalog)
                {
                    if (idx++ != targetIdx)
                        continue;

                    expectedCN = certKvp.Key;
                    foreach (var cert in certKvp.Value)
                    {
                        if (!cert.Thumbprint.Equals(expiredTP))
                        {
                            expectedCert = certKvp.Value[0];
                            break;
                        }
                    }
                    break;
                }
            }
            X509Certificate2Collection retrievedCerts = new X509Certificate2Collection();   // saves the null checks
            try
            {
                retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindBySubjectName.ToString(), expectedCN, String.Empty, doTakeMostRecentOnly: true);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
            }
            if (retrievedCerts.Count < 1)
                Console.WriteLine("FAIL: did not retrieve existing match for CN='{0}'", expectedCN);
            if (retrievedCerts.Count > 1)
                Console.WriteLine("FAIL: retrieved multiple matches for CN='{0}'", expectedCN);
            if (!VerifyCertsAreEqual(retrievedCerts[0], expectedCert))
                Console.WriteLine("FAIL: the cert retrieved by CN='{0}' (tp: {1}) does not match the expected one (tp: {2})", expectedCN, retrievedCerts[0].Thumbprint, expectedCert.Thumbprint);

            // 2. ensure we don't get partial matches
            Console.WriteLine("\n** running test case 2");
            retrievedCerts.Clear();
            try
            {
                retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindBySubjectName.ToString(), CNPrefix, String.Empty, doTakeMostRecentOnly: true);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
            }
            if (retrievedCerts.Count > 0)
                Console.WriteLine("FAIL: retrieved matches for partial CN='{0}'", CNPrefix);

            // 3. ensure we don't get expired certs
            Console.WriteLine("\n** running test case 3");
            retrievedCerts.Clear();
            try
            {
                retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindBySubjectName.ToString(), expiredCN, String.Empty, doTakeMostRecentOnly: true);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
            }
            bool shouldHaveFoundMatches = testCertCatalog[expiredCN].Count > 1;
            if (shouldHaveFoundMatches)
            {
                if (retrievedCerts.Count < 1)
                    Console.WriteLine("FAIL: did not retrieve existing non-expired match for CN='{0}'", expiredCN);
                else if (retrievedCerts.Count > 1)
                    Console.WriteLine("FAIL: retrieved more than 1 match for CN='{0}'", expiredCN);
                else if (retrievedCerts[0].Thumbprint.Equals(expiredTP))
                    Console.WriteLine("FAIL: retrieved expired cert for CN='{0}': nbf: {1}, na: {2}", expiredCN, retrievedCerts[0].NotBefore, retrievedCerts[1].NotAfter);
            }
            else if (retrievedCerts.Count > 0)
                Console.WriteLine("FAIL: retrieved expired matches for CN='{0}'", expiredCN);

            // try again, with 2 CNs
            retrievedCerts.Clear();
            try
            {
                retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindBySubjectName.ToString(), expiredCN, expectedCN, doTakeMostRecentOnly: true);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
            }
            if (retrievedCerts.Count < 1)
                Console.WriteLine("FAIL: did not retrieve existing match for CNs={'{0}', '{1}'}", expiredCN, expectedCN);
            if (retrievedCerts.Count > 1)
                Console.WriteLine("FAIL: retrieved multiple matches for CNs={'{0}', '{1}'}", expiredCN, expectedCN);
            if (retrievedCerts[0].Thumbprint.Equals(expiredTP))
                Console.WriteLine("FAIL: the cert retrieved by CN='{0}' (tp: {1}) is expired: nbf: {2}, na: {3}", expiredCN, retrievedCerts[0].Thumbprint, retrievedCerts[0].NotBefore, retrievedCerts[0].NotAfter);

            // 4. ensure we get exactly one match (and it's the most recent)
            Console.WriteLine("\n** running test case 4");
            retrievedCerts.Clear();
            try
            {
                retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindBySubjectName.ToString(), duplicateCN, String.Empty, doTakeMostRecentOnly: true);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
            }
            if (retrievedCerts.Count < 1)
                Console.WriteLine("FAIL: did not retrieve existing match for CN='{0}'", duplicateCN);
            if (retrievedCerts.Count > 1)
                Console.WriteLine("FAIL: retrieved multiple matches for duplicate CN='{0}'", duplicateCN);
            foreach (var duplicateCNCert in testCertCatalog[duplicateCN])
            {
                // if the returned cert is more recent, and the duplicate cert is not expired, continue
                if (DateTime.Compare(retrievedCerts[0].NotBefore, duplicateCNCert.NotBefore) >= 0
                    || DateTime.Compare(DateTime.Now, duplicateCNCert.NotAfter) > 0)
                {
                    continue;
                }

                Console.WriteLine(
                    "FAIL: did not retrieve the most recent match for CN:'{0}': returned tp:{1}, nbf: {2}; expected tp:{3}, nbf: {4}",
                    duplicateCN,
                    retrievedCerts[0].Thumbprint,
                    retrievedCerts[0].NotBefore,
                    duplicateCNCert.Thumbprint,
                    duplicateCNCert.NotBefore);
                break;
            }

            // 5. ensure we get a match by TP
            Console.WriteLine("\n** running test case 5");
            retrievedCerts.Clear();
            try
            {
                retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindByThumbprint.ToString(), expectedCert.Thumbprint, String.Empty, doTakeMostRecentOnly: true);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
            }
            if (retrievedCerts.Count < 1)
                Console.WriteLine("FAIL: did not retrieve existing match for TP='{0}'", expectedCert.Thumbprint);
            if (retrievedCerts.Count > 1)
                Console.WriteLine("FAIL: retrieved multiple matches for TP='{0}'", expectedCert.Thumbprint);
            if (!VerifyCertsAreEqual(retrievedCerts[0], expectedCert))
                Console.WriteLine("FAIL: retrieved wrong certificate: actual TP='{0}'; expected TP='{1}'", retrievedCerts[0].Thumbprint, expectedCert.Thumbprint);
        }

        private static X509Certificate2Collection RetrieveTestCerts(string storeNameStr, string storeLocationStr, string CNPrefix)
        {
            X509Certificate2Collection certs = null;
            Enum.TryParse<StoreName>(storeNameStr, out StoreName storeName);
            Enum.TryParse<StoreLocation>(storeLocationStr, out StoreLocation storeLocation);
            X509Store store = new X509Store(storeName, storeLocation);
            try
            {
                store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);

                certs = store.Certificates.Find(X509FindType.FindBySubjectName, CNPrefix, validOnly: false);
                if (certs.Count == 0)
                    throw new Exception(String.Format("Not a valid SF test configuration: no certificates found matching subject '{0}'.", CNPrefix));
            }
            catch (CryptographicException ce)
            {
                Console.WriteLine("caught crypto exception {0}: '{1}'", ce.HResult, ce.Message);
            }
            finally
            {
                store.Close();
            }

            return certs;
        }

        //public static void FindMatchingCertificates(StoreName storeName, StoreLocation storeLocation, string x509FindValue)
        //{
        //    var matchingCerts = new X509Certificate2Collection();

        //    using (var store = new X509Store(storeName, storeLocation, openFlags))
        //    {

        //        try
        //        {
        //            foreach (var cert in store.Certificates)
        //            {
        //                if (StringComparer.OrdinalIgnoreCase.Equals(x509FindValue, cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false)))
        //                {
        //                    matchingCerts.Add(cert);
        //                }
        //            }

        //            if (matchingCerts.Count == 0)
        //            {
        //                Console.WriteLine("could not find matching certificates for '{0}'.", x509FindValue);
        //                return;
        //            }

        //            foreach (var cert in matchingCerts)
        //            {   
        //                Console.WriteLine("\t{0} Subject: {1}, GetNameInfo: {2}", cert.Thumbprint, cert.Subject, cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false));

        //            }
        //        }
        //        catch (CryptographicException ce)
        //        {
        //            Console.WriteLine("could not find matching certificates for '{0}': {1}", x509FindValue, ce.Message);
        //        }
        //    }
        //}

        public static void DumpCertificateProperties(string x5t)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser, openFlags))
            {
                try
                {
                    var matchingCerts = store.Certificates.Find(X509FindType.FindByThumbprint, x5t, validOnly: false);

                    Console.WriteLine("retrieved certificate; enumerating properties..");
                    foreach (var cert in matchingCerts)
                    {
                        Console.WriteLine("\t{0} Subject: {1}", cert.Thumbprint, cert.Subject);

                        Console.WriteLine("\t{0} extensions:", cert.Thumbprint);
                        foreach (var prop in cert.Extensions)
                        {
                            Console.WriteLine("\t\t{0}", prop.Oid.FriendlyName);
                        }


                    }
                }
                catch (CryptographicException ce)
                {
                    Console.WriteLine("could not find certificate with thumbprint '{0}': {1}", x5t, ce.Message);
                }
            }
        }

        public static void LinkCertificates(X509Certificate2 pred, X509Certificate2 succ)
        {
            throw new NotImplementedException();
        }
    
        public static void LinkCertificates(string predX5T, string succX5T)
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser, openFlags))
            {
                // find predecessor
                try
                {
                    var matchingCerts = store.Certificates.Find(X509FindType.FindByThumbprint, predX5T, validOnly: false);

                    Console.WriteLine("retrieved certificate; enumerating properties..");
                    foreach (var cert in matchingCerts)
                    {
                        Console.WriteLine("\t{0} Subject: {1}", cert.Thumbprint, cert.Subject);

                        Console.WriteLine("\t{0} extensions:", cert.Thumbprint);
                        foreach (var prop in cert.Extensions)
                        {
                            Console.WriteLine("\t\t{0}", prop.Oid.FriendlyName);
                        }


                    }
                }
                catch (CryptographicException ce)
                {
                    Console.WriteLine("could not find certificate with thumbprint '{0}': {1}", String.Empty, ce.Message);
                }
            }
        }

        public static void UnlinkCertificates(string predX5T)
        { throw new NotImplementedException(); }
    
        public static string LoadCertificate(string x5t)
        { throw new NotImplementedException(); }

        public static void SetAccessRuleForMatchingCertificates(
            StoreLocation storeLocation, 
            StoreName storeName, 
            X509FindType findType, 
            string findValue, 
            string accountName, 
            CryptoKeyRights keyAccessMask)
        {
            // find matching certs
            X509Certificate2Collection matchingCerts = null;
            try
            {
                matchingCerts = FindMatchingCertificates(storeLocation, storeName, findType, findValue, String.Empty, doTakeMostRecentOnly: false);
            }
            catch (CryptographicException cex)
            {
                Console.WriteLine($"exception '{cex.HResult}: {cex.Message}' encountered.");
                throw;
            }

            foreach (var cert in matchingCerts)
            {
                // skip certs without private keys
                if (!cert.HasPrivateKey)
                {
                    Console.WriteLine($"skipping - no private key: '{cert.Thumbprint}': '{cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false)}'");
                    continue;
                }

                SetAccessRuleForCertificate(cert, accountName, keyAccessMask);
            }
        }

        internal static void SetAccessRuleForCertificate(X509Certificate2 cert, string accountName, CryptoKeyRights keyAccessMask)
        {
            if (!cert.HasPrivateKey) throw new ArgumentException($"cert '{cert.Thumbprint}' does not include a private key; shouldn't be here.");

            try
            {
                using (var rsaKey = cert.GetRSAPrivateKey() as RSACng)
                {
                    if (rsaKey == null)
                    {
                        throw new ArgumentException("unsupported key type - expected a RSA private key convertible to RSACng");
                    }

                    // check if this a KSP-managed key; ignore the SmartCard KSP
                    if (rsaKey.Key.Provider == CngProvider.MicrosoftSoftwareKeyStorageProvider)
                    {
                        Console.WriteLine($"Setting ACL on KSP cert '{cert.Thumbprint}: '{accountName}' - '{keyAccessMask.ToString()}");
                        SetAccessRuleOnKSPKey(rsaKey.Key, accountName, keyAccessMask);

                        return;
                    }

                    // else this is a CSP key; however, netcore won't return a RSACryptoServiceProvider object
                    // unless it absolutely has to - for non-Microsoft CSPs. That means we'll always get a RSACng
                    // object, from which there is no direct path to the RSACSP we need in order to manage access.
                    // The workaround is to build CspParameters from the cng private key, and then build a RSACSP 
                    // from it. First ensure this isn't a SmartCard provider.
                    if (rsaKey.Key.Provider == CngProvider.MicrosoftSmartCardKeyStorageProvider)
                    {
                        throw new ArgumentException("unsupported key type - the provider is Microsoft SmartCard KSP, which is not supported in this context.");
                    }

                    using (var rsaCSP = ExtractRSACSPFromCNGKey(rsaKey.Key))
                    {
                        Console.WriteLine($"Setting ACL on CSP cert '{cert.Thumbprint}: '{accountName}' - '{keyAccessMask.ToString()}");
                        SetAccessRuleOnCSPKey(rsaCSP, accountName, keyAccessMask);
                    }
                }

            }
            catch (CryptographicException cxe)
            {
                Console.WriteLine($"exception '{cxe.HResult}: {cxe.Message}' was thrown");
            }
        }

        internal static RSACryptoServiceProvider ExtractRSACSPFromCNGKey(CngKey cngKey)
        {
            CspParameters cspParams = new CspParameters
            {
                ProviderName = cngKey.Provider.Provider,
                KeyContainerName = cngKey.KeyName,
                KeyNumber = (int)KeyNumber.Exchange,            // try it as an exchange key first
                Flags = CspProviderFlags.UseExistingKey
            };

            if (cngKey.IsMachineKey) cspParams.Flags |= CspProviderFlags.UseMachineKeyStore;

            try
            {
                return new RSACryptoServiceProvider(cspParams);
            }
            catch (CryptographicException)
            {
                ;   // nop, trying next as a signature key
            }

            cspParams.KeyNumber = (int)KeyNumber.Signature;

            // let it throw;
            return new RSACryptoServiceProvider(cspParams);
        }

        internal static void SetAccessRuleOnKSPKey(CngKey key, string accountName, CryptoKeyRights keyAccessMask)
        {
            const string NCRYPT_SECURITY_DESCR_PROPERTY = "Security Descr";
            const CngPropertyOptions DACL_SECURITY_INFORMATION = (CngPropertyOptions)4;

            // retrieve existing permissions
            var existingACL = key.GetProperty(NCRYPT_SECURITY_DESCR_PROPERTY, DACL_SECURITY_INFORMATION);

            // add new rule
            CryptoKeySecurity keySec = new CryptoKeySecurity();
            keySec.SetSecurityDescriptorBinaryForm(existingACL.GetValue());
            keySec.AddAccessRule(new CryptoKeyAccessRule(accountName, keyAccessMask, AccessControlType.Allow));

            // put back
            CngProperty updatedACL = new CngProperty(existingACL.Name, keySec.GetSecurityDescriptorBinaryForm(), CngPropertyOptions.Persist | DACL_SECURITY_INFORMATION);
            key.SetProperty(updatedACL);
        }

        internal static void SetAccessRuleOnCSPKey(RSACryptoServiceProvider key, string accountName, CryptoKeyRights keyAccessMask)
        {
            // CspKeyContainerInfo does not expose the CryptoKeySecurity property in NetCore; in that
            // case, we'll simply set access at the File (key container) level; for net40 and above, 
            // we'll use the CryptoKeySecurityConstruct.
#if NETCOREAPP2_1 
            SetAccessRuleOnCSPKeyViaKeyContainer(key, accountName, keyAccessMask);
#elif NET40
            SetAccessRuleOnCSPKeyViaKeySecurity(key, accountName, keyAccessMask);
#else
            // not quite sure what we're running on, so just fail
            throw new ArgumentException("setting certificate private key access rules is not supported on the current .net framework");
#endif
        }

        private static void SetAccessRuleOnCSPKeyViaKeySecurity(RSACryptoServiceProvider cspKey, string accountName, CryptoKeyRights keyAccessMask)
        {
#if !NET40
            throw new InvalidOperationException("incorrect invocation: cannot call this function on non-net40 frameworks.");
#endif

        }

        private static void SetAccessRuleOnCSPKeyViaKeyContainer(RSACryptoServiceProvider cspKey, string accountName, CryptoKeyRights keyAccessMask)
        {
#if !NETCOREAPP2_1
            throw new InvalidOperationException("incorrect invocation: cannot call this function on non-netcore frameworks.");
#endif
            // If we're here, access is granted directly to the file corresponding to the private key. Assuming
            // this is a machine key (enforced in the calling function), the path to the key container is:
            //
            //   $env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\<key container unique name>
            //
            // e.g.: c:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\7e426a4e8a1b8c02e1105b9d7b8c056c_8c9bdc00-1bd7-4654-8e9b-8a234a4b3f88

            var keyCtrUniqueName = cspKey.CspKeyContainerInfo.UniqueKeyContainerName;
            var programDataPath = Environment.GetEnvironmentVariable("ProgramData"); // unlikely to be missing
            var rsaMachineKeyPath = "Microsoft\\Crypto\\RSA\\MachineKeys";
            var keyContainerPath = String.Format($"{programDataPath}\\{rsaMachineKeyPath}\\{keyCtrUniqueName}");

            // assert the file exists
            if (!File.Exists(keyContainerPath)) // odd situation 
            {
                throw new ArgumentException($"the expected key container file '{keyContainerPath}' does not exist; was it ephemeral or just deleted?");
            }

            try
            {
                // extract the current ACL
                var fileACL = new FileSecurity(keyContainerPath, AccessControlSections.Access);
                FileSystemRights fileSystemKeyAccessRights = FileAccessRightsFromKeySecurityAccessRights(keyAccessMask);

                // add the access rule (OS merges)
                fileACL.AddAccessRule(new FileSystemAccessRule(accountName, fileSystemKeyAccessRights, AccessControlType.Allow));

                // put back
                new FileInfo(keyContainerPath)
                    .SetAccessControl(fileACL);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"exception encountered trying to access the key container '{keyContainerPath}': {ex.Message} ({ex.HResult})");
            }

            // quick check
            Console.WriteLine("checking permissions..");
            var rules = new FileSecurity(keyContainerPath, AccessControlSections.Access)
                .GetAccessRules(
                    includeExplicit: true,
                    includeInherited: false,
                    targetType: typeof(System.Security.Principal.NTAccount));

            foreach (AuthorizationRule rule in rules)
            {
                if (rule is FileSystemAccessRule face)
                    Console.WriteLine($"ACE: {face.IdentityReference.ToString()}: {face.FileSystemRights.ToString()}");
            }
        }

        // translates access rights from the CryptoKeyRights bitmask into the equivalent file system access bitmask.
        private static FileSystemRights FileAccessRightsFromKeySecurityAccessRights(CryptoKeyRights keyAccessMask)
        {
            FileSystemRights fileAccessMask = 0;

            // build the access mask gradually 
            if (0 != (keyAccessMask & CryptoKeyRights.ReadData)) fileAccessMask |= FileSystemRights.ReadData;
            if (0 != (keyAccessMask & CryptoKeyRights.WriteData)) fileAccessMask |= FileSystemRights.WriteData;
            if (0 != (keyAccessMask & CryptoKeyRights.ReadExtendedAttributes)) fileAccessMask |= FileSystemRights.ReadExtendedAttributes;
            if (0 != (keyAccessMask & CryptoKeyRights.WriteExtendedAttributes)) fileAccessMask |= FileSystemRights.WriteExtendedAttributes;
            if (0 != (keyAccessMask & CryptoKeyRights.ReadAttributes)) fileAccessMask |= FileSystemRights.ReadAttributes;
            if (0 != (keyAccessMask & CryptoKeyRights.WriteAttributes)) fileAccessMask |= FileSystemRights.WriteAttributes;
            if (0 != (keyAccessMask & CryptoKeyRights.Delete)) fileAccessMask |= FileSystemRights.Delete;
            if (0 != (keyAccessMask & CryptoKeyRights.ReadPermissions)) fileAccessMask |= FileSystemRights.ReadPermissions;
            if (0 != (keyAccessMask & CryptoKeyRights.ChangePermissions)) fileAccessMask |= FileSystemRights.ChangePermissions;
            if (0 != (keyAccessMask & CryptoKeyRights.TakeOwnership)) fileAccessMask |= FileSystemRights.TakeOwnership;
            if (0 != (keyAccessMask & CryptoKeyRights.Synchronize)) fileAccessMask |= FileSystemRights.Synchronize;

            // FullControl is a bitmask itself                                                
            if (CryptoKeyRights.FullControl == (keyAccessMask & CryptoKeyRights.FullControl)) fileAccessMask |= FileSystemRights.FullControl;
            if (0 != (keyAccessMask & CryptoKeyRights.GenericAll)) fileAccessMask |= FileSystemRights.Modify;
            if (0 != (keyAccessMask & CryptoKeyRights.GenericExecute)) fileAccessMask |= FileSystemRights.ReadAndExecute;
            if (0 != (keyAccessMask & CryptoKeyRights.GenericWrite)) fileAccessMask |= FileSystemRights.Write;
            if (0 != (keyAccessMask & CryptoKeyRights.GenericRead)) fileAccessMask |= FileSystemRights.Read;

            return fileAccessMask;
        }
        public static bool TryValidateX509Certificate(X509Certificate2 certificate, IEnumerable<string> pinnedIssuerThumbprints)
        {
            bool isValid = false;
            X509ChainStatusFlags AllowedChainStatusForIssuerThumbprintCheck =
                X509ChainStatusFlags.UntrustedRoot |
                X509ChainStatusFlags.OfflineRevocation |
                X509ChainStatusFlags.RevocationStatusUnknown;

            HashSet<string> issuerMap = new HashSet<string>(pinnedIssuerThumbprints, StringComparer.InvariantCultureIgnoreCase);

            try
            {
                using (var chain = new X509Chain())
                {
                    chain.ChainPolicy = new X509ChainPolicy()
                    {
                        UrlRetrievalTimeout = TimeSpan.FromSeconds(30),
                        RevocationMode = X509RevocationMode.NoCheck
                    };

                    isValid = chain.Build(certificate);
                    if (chain.ChainElements == null || chain.ChainElements.Count == 0)
                    {
                        throw new InvalidOperationException("ChainElements is null or empty after chain build.");
                    }

                    if (issuerMap.Count == 0)
                    {
                        if (!isValid)
                        {
                            Console.WriteLine("Validation failed for {0}: {1}", certificate, chain.ChainStatus.ToString());
                        }

                        return isValid;
                    }

                    var chainStatus = AllowedChainStatusForIssuerThumbprintCheck;
                    foreach (var elemStatus in chain.ChainStatus)
                        chainStatus |= elemStatus.Status;

                    // Only do issuer thumbprint check if there's no other errors other than the allowed list
                    if (chainStatus == AllowedChainStatusForIssuerThumbprintCheck)
                    {
                        // For self-signed certificate there's only one element in the chain which is the certificate itself
                        var issuer = chain.ChainElements.Count > 1 ? chain.ChainElements[1] : chain.ChainElements[0];
                        return issuerMap.Contains(issuer.Certificate.Thumbprint);
                    }
                }
            }
            catch (CryptographicException cex)
            {
                Console.WriteLine("Cryptographic exception while validating certificate {0}: {1} ({2})", certificate, cex.Message, cex.HResult);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Exception while validating certificate {0}: {1}", certificate, ex);
            }


            return isValid;
        }

        private static void TraceChainInformation(X509Chain chain)
        {
            var sb = new StringBuilder();

            sb.Append("[ChainElements]\r\n");
            for (int i = 0; i < chain.ChainElements.Count; i++)
            {
                sb.AppendFormat("[{0}/{1}]\r\n{2}\r\n{3}\r\n",
                    i + 1,
                    chain.ChainElements.Count,
                    chain.ChainElements[i].ChainElementStatus.ToString(), //.Print(s => $"{s.Status}: {s.StatusInformation}", ""),
                    chain.ChainElements[i].Certificate
                    );
            }

            sb.Append("\r\n[ChainStatus]\r\n");
            sb.Append(chain.ChainStatus.ToString()); // Print(s => $"{s.Status}: {s.StatusInformation}", ""));

            Console.WriteLine(sb.ToString());
        }
    }
}
