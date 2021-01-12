using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CertExplorer
{
    public static class X509CertificateBuilder
    {
        private static readonly string PrivateKeyBeginMarker = "BEGIN PRIVATE KEY";
        private static readonly string CertificateBeginMarker = "BEGIN CERTIFICATE";

        public static X509Certificate2 FromPfx(string path)
        {
            if (String.IsNullOrWhiteSpace(path)) throw new ArgumentNullException(nameof(path));
            var ext = Path.GetExtension(path);
            if (!ext.Equals(".pfx", StringComparison.InvariantCultureIgnoreCase)) throw new ArgumentException($"file must have '.pfx' extension");

            return new X509Certificate2(path, String.Empty, X509KeyStorageFlags.EphemeralKeySet);
        }

        public static X509Certificate2 FromPem(string file1, string file2)
        {
            var ext1 = Path.GetExtension(file1);
            var ext2 = Path.GetExtension(file2);
            if (String.IsNullOrWhiteSpace(ext1)
                || !String.Equals(ext1, ".pem", StringComparison.InvariantCultureIgnoreCase)
                || !String.Equals(ext2, ".pem", StringComparison.InvariantCultureIgnoreCase))
            {
                throw new ArgumentException($"file must have '.pem' extension");
            }

            // parse files to determine which is what
            var file1Contents = File.ReadAllText(file1);
            var file2Contents = String.IsNullOrWhiteSpace(file2) ? String.Empty : File.ReadAllText(file2);

            var certString = String.Empty;
            var privateKeyString = String.Empty;

            // look for either element (cert or private key) in each of the files
            string[] fileContents = { file1Contents, file2Contents };
            foreach (var singleFile in fileContents)
            {
                // traverse the tokens, looking for the cert or private key marker; next token will be the base64-encoded bytes
                var tokens = singleFile.Split('-', StringSplitOptions.RemoveEmptyEntries);
                for (var idx = 0; idx < tokens.Length;)
                {
                    if (tokens[idx] == PrivateKeyBeginMarker)
                    {
                        privateKeyString = tokens[++idx];
                        continue;
                    }

                    if (tokens[idx] == CertificateBeginMarker)
                    {
                        certString = tokens[++idx];
                        continue;
                    }

                    idx++;
                }
            }

            // we may or may not have a cert, and/or a private key
            if (String.IsNullOrWhiteSpace(certString))
            {
                // improperly formed cert
                throw new ArgumentException($"certificate not found, invalid file type");
            }

            var certBytes = Convert.FromBase64String(certString);
            X509Certificate2 cert = new X509Certificate2(certBytes);

            // check if we have a private key
            if (String.IsNullOrWhiteSpace(privateKeyString))
            {
                // done
                return cert;
            }

            byte[] privateKeyBytes = Convert.FromBase64String(privateKeyString);
            using (var rsa = RSA.Create())
            {
                int bytesRead = 0;
                rsa.ImportPkcs8PrivateKey(privateKeyBytes, out bytesRead);

                return cert.CopyWithPrivateKey(rsa);
            }
        }

        public static X509Certificate2 FromCer(string certFilePath)
        {
            if (String.IsNullOrWhiteSpace(certFilePath)) throw new ArgumentNullException(nameof(certFilePath));
            var ext = Path.GetExtension(certFilePath);
            if (!ext.Equals(".cer", StringComparison.InvariantCultureIgnoreCase)
                && !ext.Equals(".crt", StringComparison.InvariantCultureIgnoreCase))
            {
                throw new ArgumentException($"file must have '.cer' or '.crt' extension");
            }

            var fileContents = File.ReadAllText(certFilePath);
            var certBytes = Convert.FromBase64String(fileContents);

            return new X509Certificate2(certBytes);
        }

        public static X509Certificate2 FromFileList(List<string> filePaths)
        {
            var filePath = filePaths[0];
            var ext = Path.GetExtension(filePath);
            if (ext.Equals(".pfx", StringComparison.InvariantCultureIgnoreCase))
            {
                return FromPfx(filePath);
            }

            if (ext.Equals(".cer", StringComparison.InvariantCultureIgnoreCase))
            {
                return FromCer(filePath);
            }

            if (ext.Equals(".pem", StringComparison.InvariantCultureIgnoreCase)
                || ext.Equals(".key", StringComparison.InvariantCultureIgnoreCase))
            {
                return FromPem(filePath, filePaths.Count > 1 ? filePaths[1] : String.Empty);
            }

            throw new ArgumentException($"unsupported certificate file format: '{ext}'");
        }
    }
}
