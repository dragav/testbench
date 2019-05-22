using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace UninstallX509Cert
{
    public class X509CertAccess
    {
        public static bool TryRemoveX509CertificateByThumbprint(string x5t, StoreLocation location, StoreName name)
        {
            try
            {
                Console.WriteLine("attempting to remove certificate '{0}' from {1}\\{2}", x5t, location, name);
                using (var store = new X509Store(name, location, OpenFlags.MaxAllowed | OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite))
                {
                    Console.WriteLine("successfully opened cert store..");
                    foreach (var certMatch in store.Certificates.Find(X509FindType.FindByThumbprint, x5t, validOnly: false))
                    {
                        using (certMatch)
                        {
                            Console.WriteLine("found matching certificate: {0}; subject: {1}; removing..", x5t, certMatch.SubjectName);
                            // remove the cert
                            store.Remove(certMatch);
                            Console.WriteLine("successfully removed certificate.");

                            return true;
                        }
                    }

                    Console.WriteLine("Could not find a match for '{0}' in the store.");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("failed to remove certificate '{0}' from {1}\\{2}: {3}", x5t, location, name, e.ToString());
            }

            return false;
        }

        public static bool TryRemoveX509CertificateBySubject(string subjectPattern, StoreLocation location, StoreName name)
        {
            try
            {
                Console.WriteLine("attempting to remove certificate '{0}' from {1}\\{2}", subject, location, name);
                using (var store = new X509Store(name, location, OpenFlags.MaxAllowed | OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite))
                {
                    Console.WriteLine("successfully opened cert store..");
                    foreach (var certificate in store.Certificates)
                    {
                        using (certificate)
                        {
                            if (certificate.Subject.Contains(subjectPattern))
                            {
                                Console.WriteLine("Found a cert match: certificate subject: '{0}'; search pattern: '{1}'", certificate.Subject, subjectPattern);
                            }
                        }
                    }

                    foreach (var certMatch in store.Certificates.Find(X509FindType.FindBySubjectName, subject, validOnly: false))
                    {
                        using (certMatch)
                        {
                            Console.WriteLine("found matching certificate: {0}; subject: {1}; removing..", x5t, certMatch.SubjectName);
                            // remove the cert
                            store.Remove(certMatch);
                            Console.WriteLine("successfully removed certificate.");

                            return true;
                        }
                    }

                    Console.WriteLine("Could not find a match for '{0}' in the store.");
                }
            }
            catch (Exception e)
            {
                Console.WriteLine("failed to remove certificate '{0}' from {1}\\{2}: {3}", x5t, location, name, e.ToString());
            }

            return false;
        }


    }
}
