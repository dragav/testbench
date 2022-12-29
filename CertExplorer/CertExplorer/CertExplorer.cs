using System;
using System.Collections.Generic;
using System.IO;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
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
    private static readonly string WinFabCNPrefix = "WinFabric-Test-";
    private static readonly uint CertRenewalPropId = 64;

    #region public methods
    public delegate bool IsCertificateAMatchForFindValue(X509Certificate2 enumeratedCert, string findValue);

    public static bool IsMatchByThumbprint(X509Certificate2 enumeratedCert, string x509FindValue)
    {
        return StringComparer.OrdinalIgnoreCase.Equals(x509FindValue, enumeratedCert.Thumbprint);
    }

    public static bool IsMatchBySubjectCommonName(X509Certificate2 enumeratedCert, string x509FindValue)
    {
        /// the find value, if used with X509FindType.FindBySubject, yields erroneous matches: mismatching casing, or certificates
        /// whose subject is a superstring of the one we're looking for. FindByDistinguishedName fails as well - .net does not seem
        /// to support finding a cert by its own DN. At the recommendation of the CLR team, the best option is to do an exact match 
        /// of the find value with a certificate's SimpleName, which is the 'name' value calculated by a definitely-not-simple algorithm.
        /// We're relaxing the exact match to a case-insensitive one; this isn't what the runtime is doing, but the intent here is 
        /// to find/compare DNS-type names. 
        return StringComparer.OrdinalIgnoreCase.Equals(x509FindValue, enumeratedCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false));
    }

    public static bool AnyMatch(X509Certificate2 cert, string findValue) => true;

    public static bool NoMatch(X509Certificate2 cert, string findValue) => false;

    public static Logger Logger { get; set; }
    public static CertExplorerConfig Config { get; set; }

    public static X509Certificate2Collection FindMatchingCertificates(
        string storeLocationStr,
        string storeNameStr,
        string findTypeStr,
        string findValue,
        string secondaryFindValue,
        bool doTakeMostRecentOnly,
        bool excludeExpiredCerts)
    {
        if (!Enum.TryParse(storeLocationStr, out StoreLocation storeLocation))
        {
            throw new ArgumentException("X509FindType in cluster manifest is not of proper enum value");
        }

        if (!Enum.TryParse(findTypeStr, out X509FindType findType))
        {
            throw new ArgumentException("X509FindType in cluster manifest is not of proper enum value");
        }

        return FindMatchingCertificates(storeLocation, storeNameStr, findType, findValue, secondaryFindValue, doTakeMostRecentOnly, excludeExpiredCerts);
    }

    public static X509Certificate2Collection FindMatchingCertificates(
        StoreLocation storeLocation,
        StoreName storeName,
        X509FindType findType,
        string findValue,
        string secondaryFindValue,
        bool doTakeMostRecentOnly,
        bool excludeExpiredCerts)
    {
        return FindMatchingCertificates(storeLocation, storeName.ToString(), findType, findValue, secondaryFindValue, doTakeMostRecentOnly, excludeExpiredCerts);
    }

    public static X509Certificate2Collection FindMatchingCertificates(
        StoreLocation storeLocation,
        string storeName,
        X509FindType findType,
        string findValue,
        string secondaryFindValue,
        bool doTakeMostRecentOnly,
        bool excludeExpiredCerts,
        bool doLog = false)
    {
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
                throw new ArgumentException($"Unsupported X509FindType: '{findType}'; supported values are FindByThumbprint and FindBySubjectName");
        }

        // SFRP is generating ClusterManifests setting this value to StoreLocation.LocalMachine
        // Using hard-coded value of StoreLocation.CurrentUser for TP9 till SFRP is updated to set this value appropriately.
        var storeCertificates = X509CertificateEnumerator.Enumerate(storeLocation, storeName);
        var matchingCertificates = new X509Certificate2Collection();

        X509Certificate2 selectedCert = null;
        try
        {
            bool isTimeValidCert = false;
            bool isExpiredCert = false;
            bool anyMatchFound = false;
            DateTime now = DateTime.Now;        // cert validity is presented in local time.

            var findValues = new List<string>() { findValue };
            if (!string.IsNullOrEmpty(secondaryFindValue))
            {
                findValues.Add(secondaryFindValue);
            }

            foreach (var value in findValues)
            {
                Log($"Finding matching certificates for find value '{findValue}'; excludeExpiredCerts = '{excludeExpiredCerts}'");
                foreach (var enumeratedCert in storeCertificates)
                {
                    isExpiredCert = DateTime.Compare(now, enumeratedCert.NotAfter) > 0;
                    isTimeValidCert = !(excludeExpiredCerts && isExpiredCert)
                                    && DateTime.Compare(now, enumeratedCert.NotBefore) >= 0;
                    if (matchCert(enumeratedCert, value)
                        && isTimeValidCert)
                    {
                        anyMatchFound = true;

                        Log($"Found matching certificate: Thumbprint {enumeratedCert.Thumbprint}, NotBefore {enumeratedCert.NotBefore}, NotAfter {enumeratedCert.NotAfter}, Subject {enumeratedCert.Subject}");

                        if (!doTakeMostRecentOnly)
                        {
                            // if taking all, add it here and continue
                            matchingCertificates.Add(enumeratedCert);
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
                Log($"Selected certificate: Thumbprint {selectedCert.Thumbprint}, NotBefore {selectedCert.NotBefore}, NotAfter {selectedCert.NotAfter}, Subject {selectedCert.Subject}");

                matchingCertificates.Add(selectedCert);
            }
            else
            {
                Log($"No {(anyMatchFound ? "valid" : "matching")} certificate found: StoreName {storeName}, StoreLocation {storeLocation}, FindType {findType}, FindValue {findValue}");
            }
        }
        catch (Exception e)
        {
            Console.WriteLine($"Exception encountering matching certificates: {e.Message}");
        }

        if (matchingCertificates.Count == 0)
        {
            throw new InvalidOperationException("Could not load primary and secondary certificate");
        }

        return matchingCertificates;
    }

    /// <summary>
    /// Validates a given certificate against an expected thumbprint, and according to the specified parameters.
    /// </summary>
    /// <param name="certificate">Certificate to validate.</param>
    /// <param name="expectedThumbprint">Expected thumbprint match (SHA1 thumbprint.)</param>
    /// <param name="allowExpiredSelfSignedCerts">Boolean indicating whether expired self-signed certificates are accepted.</param>
    /// <param name="isValidCertificate">Boolean indicating whether the certificate is valid according to the rule.</param>
    /// <param name="x509ChainStatuses">Output returning chain statuses for custom validation by the caller.</param>
    /// <returns>True if validation was completed succesfully, and false otherwise.</returns>
    /// <remarks>
    /// A true response does not indicate that the cert is valid, only that validation was completed without error.
    /// </remarks>
    public static bool TryValidateCertificate(
        X509Certificate2 certificate,
        IsCertificateAMatchForFindValue matchingFn,
        string expectedFindValue,
        IReadOnlyCollection<string> expectedIssuerThumbprints,
        X509ChainStatusFlags allowedChainStatus,
        out bool isValidCertificate,
        out X509ChainStatus[] x509ChainStatuses)
    {
        // This does not constitute a 'deep' validation of the certificate, as its intended usage is not available (and
        // we don't want to unnecessarily complicate this code.) The final authority on whether a certificate is valid
        // remains the runtime - this validation is meant more for pre-/first-pass scenarios. As such, the validation
        // is generally a bit more relaxed than the verification performed on the same certificate at authentication
        // time. 
        //
        // This verification will assess the following:
        //   - the certificate is a valid certificate object
        //   - the certificate's chain can be built
        //   - the certificate is time-valid at a point in the near future
        //   - the matchingFn applied to the certificate returns true
        //   - if specified, the certificate's issuer must match one of the issuer TPs
        //   - if the chain failed, it must match the allowed status
        // 
        // Application or certificate policies, as well as Enhanced Key Usages are not being validated.
        // Any chain statuses are returned to the caller for additional handling.

        if (certificate == null) throw new ArgumentNullException(nameof(certificate));
        if (String.IsNullOrWhiteSpace(expectedFindValue)) throw new ArgumentNullException(nameof(expectedFindValue));

        bool completedValidation = false;
        isValidCertificate = true;
        x509ChainStatuses = null;

        try
        {
            // first check the find value
            isValidCertificate = matchingFn(certificate, expectedFindValue);
            if (!isValidCertificate)
            {
                Log($"certificate '{certificate.Thumbprint}' does not match expected find value '{expectedFindValue}'");

                return true;    // validation complete
            }

            // build and validate the chain
            var chain = new X509Chain(useMachineContext: true)
            {
                ChainPolicy = new X509ChainPolicy
                {
                    UrlRetrievalTimeout = TimeSpan.FromSeconds(30.0),   // allow for slow CRL/AIA response; this isn't in the user path
                    VerificationTime = DateTime.Now.AddMinutes(5.0),    // expect the cert to be valid after rollout (5 min is arbitrary, but allows for testing)
                    RevocationMode = X509RevocationMode.NoCheck         // no revocation check on thumbprint pinning
                }
            };

            bool isValidChain = chain.Build(certificate);
            if (!isValidChain)
            {
                // print a detailed error message reflecting the chain status
                x509ChainStatuses = chain.ChainStatus;

                StringBuilder errorStrBuilder = new StringBuilder();
                errorStrBuilder.AppendFormat($"chain building failed for certificate '{certificate.Thumbprint}'; enumerating the status for each of the {chain.ChainElements.Count} elements:");
                int idx = 0;
                foreach (var status in chain.ChainStatus)
                {
                    errorStrBuilder.AppendFormat($"\n\telement {idx}: '{chain.ChainElements[idx].Certificate.Thumbprint}': {chain.ChainStatus[idx].StatusInformation} ({chain.ChainStatus[idx].Status.ToString()})");
                }

                Log(errorStrBuilder.ToString());
                // continue validation, chain may have failed with an acceptable error
            }

            // if issuers are specified, they must match
            if (expectedIssuerThumbprints.Count > 0)
            {
                // reset valid status
                isValidCertificate = false;
                var issuerChainElementIdx = chain.ChainElements.Count > 1 ? 1 : 0;
                var issuerTP = chain.ChainElements[issuerChainElementIdx].Certificate.Thumbprint;

                foreach (var expectedIssuerTP in expectedIssuerThumbprints)
                {
                    if (issuerTP.Equals(expectedIssuerTP, StringComparison.OrdinalIgnoreCase))
                    {
                        isValidCertificate = true;
                        break;
                    }
                }
            }

            if (isValidCertificate
                && !isValidChain)
            {
                // mask out any allowed error statuses
                isValidCertificate &= chain.ChainStatus[0].Status == X509ChainStatusFlags.NoError
                        || (X509ChainStatusFlags)(chain.ChainStatus[0].Status | allowedChainStatus) == allowedChainStatus;
            }

            completedValidation = true;
        }
        catch (CryptographicException cex)
        {
            Log($"crypto exception encountered building the chain of certificate '{certificate.Thumbprint}': {cex.Message} ({cex.HResult})");
        }
        catch (Exception ex)
        {
            Log($"generic exception encountered validating certificate '{certificate.Thumbprint}': {ex.Message} ({ex.HResult})");
        }

        return completedValidation;
    }

    public static bool IsLinkedCertificate(X509Certificate2 targetCert, out string linkedToTP)
    {
        linkedToTP = string.Empty;

        if (targetCert == null) throw new ArgumentNullException(nameof(targetCert));

        bool result = false;

        try
        {
            linkedToTP = GetCertificateContextProperty(targetCert, CertRenewalPropId);
            result = true;
        }
        catch (Exception ex)
        {
            Log($"Failed to retrieve prop id {CertRenewalPropId} from certificate {targetCert.Thumbprint}: {ex}");
        }

        return result;
    }
    #endregion // public methods

    #region test methods
    /// <summary>
    /// Sorts the specified certificates into a map of subjects to matching certificates.
    /// Also returns the keys (and thumbprint) of duplicate and expired certs.
    /// </summary>
    /// <param name="testCerts"></param>
    /// <param name="duplicateCN"></param>
    /// <param name="expiredCN"></param>
    /// <param name="expiredTP"></param>
    /// <returns></returns>
    private static Dictionary<string, X509Certificate2Collection> InventoryTestCerts(
        X509Certificate2Collection testCerts, 
        out string duplicateCN, 
        out string expiredCN,
        out string expiredTP,
        out bool haveTimeValidCert,
        out string revokedTP)
    {
        var certMap = new Dictionary<string, X509Certificate2Collection>();

        duplicateCN = String.Empty;
        expiredCN = String.Empty;
        expiredTP = String.Empty;
        haveTimeValidCert = false;
        revokedTP = String.Empty;

        // inventory them, to ensure we have all the expected kinds of certs
        bool haveDuplicateCNs = false;
        bool haveExpiredCerts = false;
        bool excludeExpiredCerts = true;
        var now = DateTime.Now;
        foreach (var testCert in testCerts)
        {
            var cn = testCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);

            bool isExpiredCert = now > testCert.NotAfter;
            bool isTimeValidCert = !(excludeExpiredCerts && isExpiredCert)
                            && now >= testCert.NotBefore;
            Log($"enumerated: CN={cn}, TP={testCert.Thumbprint}, NBF={testCert.NotBefore}, NA={testCert.NotAfter}; is{(isTimeValidCert ? String.Empty : " not")} time-valid");

            haveTimeValidCert |= isTimeValidCert;

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

            using (var chain = new X509Chain(useMachineContext: true))
            {
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Offline;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EndCertificateOnly;

                var hasValidChain = chain.Build(testCert);
                if (!hasValidChain)
                {
                    Log($"failed to build chain for certificate CN={testCert.SubjectName}, TP={testCert.Thumbprint}");
                    var leafStatus = chain.ChainStatus[0];

                    if ((leafStatus.Status & X509ChainStatusFlags.Revoked) == X509ChainStatusFlags.Revoked)
                    {
                        revokedTP = testCert.Thumbprint;
                    }
                }
            }

            certMap[cn].Add(testCert);
        }

        Log($"inventoried {certMap.Count} distinct certs; have duplicate names: {haveDuplicateCNs}; have expired certs: {haveExpiredCerts}");

        return certMap;
    }

    private static bool VerifyCertsAreEqual(X509Certificate2 lhs, X509Certificate2 rhs)
    {
        return lhs.Thumbprint.Equals(rhs.Thumbprint);
    }

    public static void TestCertificateRetrieval()
    {
        // retrieve the winfab certs with SubjectName matching
        var testCerts = RetrieveTestCerts(StoreNamePersonal, StoreLocationLM, WinFabCNPrefix);

        // inventory them to ensure we have certs for all test scenarios
        var testCertCatalog = InventoryTestCerts(testCerts, out string duplicateCN, out string expiredCN, out string expiredTP, out bool haveTimeValidCert, out string revokedTP);

        // start running the tests
        // 1. ensure we get an exact match
        Log("\n** running test case 1");
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
            retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindBySubjectName.ToString(), expectedCN, String.Empty, doTakeMostRecentOnly: true, excludeExpiredCerts: true);
        }
        catch (Exception ex)
        {
            Log($"Caught exception: {ex.HResult}: {ex.Message}");
        }
        if (retrievedCerts.Count < 1)
            Log($"FAIL: did not retrieve existing match for CN='{expectedCN}'");
        if (retrievedCerts.Count > 1)
            Log($"FAIL: retrieved multiple matches for CN='{expectedCN}'");
        if (!VerifyCertsAreEqual(retrievedCerts[0], expectedCert))
            Log($"FAIL: the cert retrieved by CN='{expectedCN}' (tp: {retrievedCerts[0].Thumbprint}) does not match the expected one (tp: {expectedCert.Thumbprint})");

        // 2. ensure we don't get partial matches
        Log("\n** running test case 2");
        retrievedCerts.Clear();
        try
        {
            retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindBySubjectName.ToString(), WinFabCNPrefix, String.Empty, doTakeMostRecentOnly: true, excludeExpiredCerts: true);
        }
        catch (Exception ex)
        {
            Log($"Caught exception: {ex.HResult}: {ex.Message}");
        }
        if (retrievedCerts.Count > 0)
            Log($"FAIL: retrieved matches for partial CN='{WinFabCNPrefix}'");

        // 3. ensure we don't get expired certs
        Console.WriteLine("\n** running test case 3");
        retrievedCerts.Clear();
        try
        {
            retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindBySubjectName.ToString(), expiredCN, String.Empty, doTakeMostRecentOnly: true, excludeExpiredCerts: true);
        }
        catch (Exception ex)
        {
            Log($"Caught exception: {ex.HResult}: {ex.Message}");
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
            retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindBySubjectName.ToString(), expiredCN, expectedCN, doTakeMostRecentOnly: true, excludeExpiredCerts: true);
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
            retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindBySubjectName.ToString(), duplicateCN, String.Empty, doTakeMostRecentOnly: true, excludeExpiredCerts: true);
        }
        catch (Exception ex)
        {
            Log($"Caught exception: {ex.HResult}: {ex.Message}");
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
            retrievedCerts = FindMatchingCertificates(StoreNamePersonal, StoreLocationLM, X509FindType.FindByThumbprint.ToString(), expectedCert.Thumbprint, String.Empty, doTakeMostRecentOnly: true, excludeExpiredCerts: true);
        }
        catch (Exception ex)
        {
            Log($"Caught exception: {ex.HResult}: {ex.Message}");
        }
        if (retrievedCerts.Count < 1)
            Console.WriteLine("FAIL: did not retrieve existing match for TP='{0}'", expectedCert.Thumbprint);
        if (retrievedCerts.Count > 1)
            Console.WriteLine("FAIL: retrieved multiple matches for TP='{0}'", expectedCert.Thumbprint);
        if (!VerifyCertsAreEqual(retrievedCerts[0], expectedCert))
            Console.WriteLine("FAIL: retrieved wrong certificate: actual TP='{0}'; expected TP='{1}'", retrievedCerts[0].Thumbprint, expectedCert.Thumbprint);
    }

    private static X509Certificate2 FindRandomNonExpiredTestCertificate(Dictionary<string, X509Certificate2Collection> certMap)
    {
        // pick a cn at random, and pick a non-expired cert with that cn
        // very unlikely that all certs in the map are expired, deal with this later
        // in any case, make a number of attempts - for now the number of keys; tweak if flaky.
        for (var attempt = 0; attempt < certMap.Keys.Count; attempt++)
        {
            var targetIdx = new Random((int)DateTime.UtcNow.Ticks).Next(certMap.Count - 1);
            var idx = 0; // grr; no index-based access
            foreach (var certKvp in certMap)
            {
                if (idx++ != targetIdx)
                    continue;

                foreach (var cert in certKvp.Value)
                {
                    if (cert.NotAfter >= DateTime.Now
                        && cert.NotBefore <= DateTime.Now)
                    {
                        return cert;
                    }
                }
            }
        }

        throw new ArgumentException("can't find a non-expired cert!");
    }

    public static void TestCertificateValidation()
    {
        int testsRun = 0, testsPassed = 0;
        // retrieve the winfab certs with SubjectName matching
        var testCerts = RetrieveTestCerts(StoreNamePersonal, StoreLocationLM, WinFabCNPrefix);

        // inventory them to ensure we have certs for all test scenarios
        var testCertCatalog = InventoryTestCerts(testCerts, out string duplicateCN, out string expiredCN, out string expiredTP, out bool haveTimeValidCert, out string revokedTP);

        // 1. validate valid cert by thumbprint
        Console.WriteLine("\n** running test case 1: validate cert by thumbprint");
        bool isValid = false;
        bool shouldBeValid = true;
        bool passed = false;
        X509ChainStatus[] fullChainStatus = null;
        List<string> issuerTPs = new List<string> { };
        try
        {
            X509Certificate2 targetCert = FindRandomNonExpiredTestCertificate(testCertCatalog);

            bool validationCompleted = TryValidateCertificate(
                targetCert,
                IsMatchByThumbprint,
                targetCert.Thumbprint,
                issuerTPs,
                X509ChainStatusFlags.UntrustedRoot,
                out isValid,
                out fullChainStatus);

            passed = validationCompleted 
                && isValid == shouldBeValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
        }
        testsRun++;
        testsPassed += passed ? 1 : 0;
        Console.WriteLine("Test case 1 {0}", passed ? "PASSED": "FAILED");

        // 2. validate expired cert by thumbprint, not allowing expired
        Console.WriteLine("\n** running test case 2: validate expired cert by thumbprint, not allowing expired certs");
        isValid = false;
        shouldBeValid = false;
        passed = false;
        try
        {
            X509Certificate2 targetCert = testCertCatalog[expiredCN][0];

            bool validationCompleted = TryValidateCertificate(
                targetCert,
                IsMatchByThumbprint,
                targetCert.Thumbprint,
                issuerTPs,
                X509ChainStatusFlags.UntrustedRoot,
                out isValid,
                out fullChainStatus);

            passed = validationCompleted
                && isValid == shouldBeValid;
        }
        catch (Exception ex)
        {
            Log($"Caught exception: {ex.HResult}: {ex.Message}");
        }
        testsRun++;
        testsPassed += passed ? 1 : 0;
        Console.WriteLine("Test case 2 {0}", passed ? "PASSED" : "FAILED");

        // 3. validate expired cert by thumbprint, allowing expired
        Console.WriteLine("\n** running test case 3: validate expired cert by thumbprint, allowed expired certs");
        isValid = false;
        shouldBeValid = true;
        passed = false;
        try
        {
            X509Certificate2 targetCert = testCertCatalog[expiredCN][0];

            bool validationCompleted = TryValidateCertificate(
                targetCert,
                IsMatchByThumbprint,
                targetCert.Thumbprint,
                issuerTPs,
                X509ChainStatusFlags.UntrustedRoot | X509ChainStatusFlags.NotTimeValid,
                out isValid,
                out fullChainStatus);

            passed = validationCompleted
                && isValid == shouldBeValid;
        }
        catch (Exception ex)
        {
            Log($"Caught exception: {ex.HResult}: {ex.Message}");
        }
        testsRun++;
        testsPassed += passed ? 1 : 0;
        Console.WriteLine("Test case 3 {0}", passed ? "PASSED" : "FAILED");

        // 4. validate mismatching cert by thumbprint
        Console.WriteLine("\n** running test case 4: validate mismatching cert by thumbprint");
        isValid = false;
        shouldBeValid = false;
        passed = false;
        try
        {
            X509Certificate2 targetCert = FindRandomNonExpiredTestCertificate(testCertCatalog);

            bool validationCompleted = TryValidateCertificate(
                targetCert,
                IsMatchByThumbprint,
                "this_is_not_a_thumbprint",
                issuerTPs,
                X509ChainStatusFlags.UntrustedRoot,
                out isValid,
                out fullChainStatus);

            passed = validationCompleted
                && isValid == shouldBeValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
        }
        testsRun++;
        testsPassed += passed ? 1 : 0;
        Console.WriteLine("Test case 4 {0}", passed ? "PASSED" : "FAILED");

        // 5. validate cert by subject, no issuers
        Console.WriteLine("\n** running test case 5: validate cert by subject, no issuers");
        isValid = false;
        shouldBeValid = true;
        passed = false;
        try
        {
            // this test assumes a typical SF environment, with WinFabric- certificates issued by
            // WinFabric-Test-TA-CA; the test also assumes the issuer is a trusted room on the 
            // machine running the test. If this test fails, verify these assumptions.
            X509Certificate2 targetCert = FindRandomNonExpiredTestCertificate(testCertCatalog);

            bool validationCompleted = TryValidateCertificate(
                targetCert,
                IsMatchBySubjectCommonName,
                targetCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                issuerTPs,
                X509ChainStatusFlags.NoError,
                out isValid,
                out fullChainStatus);

            passed = validationCompleted
                && isValid == shouldBeValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
        }
        testsRun++;
        testsPassed += passed ? 1 : 0;
        Console.WriteLine("Test case 5 {0}", passed ? "PASSED" : "FAILED");

        // 6. validate cert by subject, issuers
        Console.WriteLine("\n** running test case 6: validate cert by subject and issuers");
        isValid = false;
        shouldBeValid = true;
        passed = false;
        try
        {
            X509Certificate2 targetCert = FindRandomNonExpiredTestCertificate(testCertCatalog);

            // need to find the issuer; we could hard-code the TP but it's safer to build the chain
            X509Chain chain = new X509Chain(useMachineContext: true);
            if (!chain.Build(targetCert)
                || chain.ChainElements.Count <= 1)
                throw new ArgumentException($"could not build the chain for certificate '{targetCert.Thumbprint}', or it is self-signed.");

            issuerTPs.Add(chain.ChainElements[1].Certificate.Thumbprint);
            bool validationCompleted = TryValidateCertificate(
                targetCert,
                IsMatchBySubjectCommonName,
                targetCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                issuerTPs,
                X509ChainStatusFlags.UntrustedRoot,
                out isValid,
                out fullChainStatus);

            passed = validationCompleted
                && isValid == shouldBeValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
        }
        testsRun++;
        testsPassed += passed ? 1 : 0;
        Console.WriteLine("Test case 6 {0}", passed ? "PASSED" : "FAILED");

        // 7. validate cert by subject, mismatching issuer
        Console.WriteLine("\n** running test case 7: validate cert by subject with mismatching issuer");
        isValid = false;
        shouldBeValid = false;
        passed = false;
        issuerTPs.Clear();
        try
        {
            X509Certificate2 targetCert = FindRandomNonExpiredTestCertificate(testCertCatalog);

            issuerTPs.Add("this_is_not_a_thumbprint");
            bool validationCompleted = TryValidateCertificate(
                targetCert,
                IsMatchBySubjectCommonName,
                targetCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                issuerTPs,
                X509ChainStatusFlags.UntrustedRoot,
                out isValid,
                out fullChainStatus);

            passed = validationCompleted
                && isValid == shouldBeValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
        }
        testsRun++;
        testsPassed += passed ? 1 : 0;
        Console.WriteLine("Test case 7 {0}", passed ? "PASSED" : "FAILED");

        // 8. validate expired cert by subject
        Console.WriteLine("\n** running test case 8: validate expired cert by subject and issuer");
        isValid = false;
        shouldBeValid = false;
        passed = false;
        issuerTPs.Clear();
        try
        {
            X509Certificate2 targetCert = testCertCatalog[expiredCN][0];

            bool validationCompleted = TryValidateCertificate(
                targetCert,
                IsMatchBySubjectCommonName,
                targetCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false),
                issuerTPs,
                X509ChainStatusFlags.UntrustedRoot,
                out isValid,
                out fullChainStatus);

            passed = validationCompleted
                && isValid == shouldBeValid;
        }
        catch (Exception ex)
        {
            Console.WriteLine("Caught exception: {0}: {1}", ex.HResult, ex.Message);
        }
        testsRun++;
        testsPassed += passed ? 1 : 0;
        Console.WriteLine("Test case 8 {0}", passed ? "PASSED" : "FAILED");

        Console.WriteLine($"========== Test run complete: {testsPassed} out of {testsRun} passed.");
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
    #endregion // test methods

    #region utils

    public static void DumpCertificateProperties(string x5t)
    {
        OpenFlags openFlags = OpenFlags.IncludeArchived | OpenFlags.MaxAllowed | OpenFlags.OpenExistingOnly;

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
        OpenFlags openFlags = OpenFlags.IncludeArchived | OpenFlags.MaxAllowed | OpenFlags.OpenExistingOnly;

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
                chain.ChainElements[i].Certificate);
        }

        sb.Append("\r\n[ChainStatus]\r\n");
        sb.Append(chain.ChainStatus.ToString()); // Print(s => $"{s.Status}: {s.StatusInformation}", ""));

        Console.WriteLine(sb.ToString());
    }

    private static void Log(string message)
    {
        LogLevel level = Config == null ? LogLevel.Verbose : Config.LogLevel;
        if (Logger != null)
        {
            Logger.Log(level, message);
        }
        else
        {
            Console.WriteLine(message);
        }
    }
    #endregion // utils

    #region Structures
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CRYPT_KEY_PROV_INFO
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszContainerName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszProvName;
        public uint dwProvType;
        public uint dwFlags;
        public uint cProvParam;
        public IntPtr rgProvParam;
        public uint dwKeySpec;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CRYPTOAPI_BLOB
    {
        public uint cbData;
        public IntPtr pbData;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CERT_DSS_PARAMETERS
    {
        public CRYPTOAPI_BLOB p;
        public CRYPTOAPI_BLOB q;
        public CRYPTOAPI_BLOB g;
    }
#endregion

[DllImport("crypt32.dll")]
public static extern bool CertGetCertificateContextProperty(IntPtr pCertContext, uint dwPropId, IntPtr pvData, ref uint pcbData);


public static string GetCertificateContextProperty(X509Certificate2 certificate, uint propId)
{
    try
    {
        // get prop existence and size, if set
        IntPtr certhandle = certificate.Handle;
        uint pcbData = 0;
        if (!CertGetCertificateContextProperty(certhandle, propId, IntPtr.Zero, ref pcbData))
        {
            Console.WriteLine($"Property {propId} could not be retrieved.");

            return string.Empty;
        }

        // get prop and convert to string
        IntPtr unsafeTpBuf = Marshal.AllocHGlobal((int)pcbData);
        try
        {
            if (!CertGetCertificateContextProperty(certhandle, propId, unsafeTpBuf, ref pcbData))
            {
                throw new Exception($"Failed to fetch property {propId} (2nd try)");
            }

            byte[] tpBuf = new byte[pcbData];
            Marshal.Copy(unsafeTpBuf, tpBuf, (int)0, (int)pcbData);

            string returnTP = BitConverter.ToString(tpBuf, 0, (int)pcbData);

            return System.Text.RegularExpressions.Regex.Replace(returnTP, "-", "");
        }
        finally
        {
            Marshal.FreeHGlobal(unsafeTpBuf);
        }
    }
    finally
    {
    }
    throw new Exception("Failed to fetch the Certificate Context Property");
}

#region ACLing
#if NET40
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
        matchingCerts = FindMatchingCertificates(storeLocation, storeName, findType, findValue, String.Empty, doTakeMostRecentOnly: false, excludeExpiredCerts: true);
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
#endif

#endregion // ACLing

#region cutting room floor
//public static bool TryValidateX509Certificate(X509Certificate2 certificate, IEnumerable<string> pinnedIssuerThumbprints)
//{
//    bool isValid = false;
//    X509ChainStatusFlags AllowedChainStatusForIssuerThumbprintCheck =
//        X509ChainStatusFlags.UntrustedRoot |
//        X509ChainStatusFlags.OfflineRevocation |
//        X509ChainStatusFlags.RevocationStatusUnknown;

//    HashSet<string> issuerMap = new HashSet<string>(pinnedIssuerThumbprints, StringComparer.InvariantCultureIgnoreCase);

//    try
//    {
//        using (var chain = new X509Chain())
//        {
//            chain.ChainPolicy = new X509ChainPolicy()
//            {
//                UrlRetrievalTimeout = TimeSpan.FromSeconds(30),
//                RevocationMode = X509RevocationMode.NoCheck
//            };

//            isValid = chain.Build(certificate);
//            if (chain.ChainElements == null || chain.ChainElements.Count == 0)
//            {
//                throw new InvalidOperationException("ChainElements is null or empty after chain build.");
//            }

//            if (issuerMap.Count == 0)
//            {
//                if (!isValid)
//                {
//                    Console.WriteLine("Validation failed for {0}: {1}", certificate, chain.ChainStatus.ToString());
//                }

//                return isValid;
//            }

//            var chainStatus = AllowedChainStatusForIssuerThumbprintCheck;
//            foreach (var elemStatus in chain.ChainStatus)
//                chainStatus |= elemStatus.Status;

//            // Only do issuer thumbprint check if there's no other errors other than the allowed list
//            if (chainStatus == AllowedChainStatusForIssuerThumbprintCheck)
//            {
//                // For self-signed certificate there's only one element in the chain which is the certificate itself
//                var issuer = chain.ChainElements.Count > 1 ? chain.ChainElements[1] : chain.ChainElements[0];
//                return issuerMap.Contains(issuer.Certificate.Thumbprint);
//            }
//        }
//    }
//    catch (CryptographicException cex)
//    {
//        Console.WriteLine("Cryptographic exception while validating certificate {0}: {1} ({2})", certificate, cex.Message, cex.HResult);
//    }
//    catch (Exception ex)
//    {
//        Console.WriteLine("Exception while validating certificate {0}: {1}", certificate, ex);
//    }


//    return isValid;
//}

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
#endregion
}
}
