﻿
namespace TokenTool
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Text;
    using System.Threading.Tasks;
    using Microsoft.Identity.Client;
    using Microsoft.IdentityModel.JsonWebTokens;
    using Microsoft.IdentityModel.Tokens;

    class AccessTokenAcquirer
    {
        private readonly StoreLocation location_;
        private readonly StoreName storeName_;
        private IConfidentialClientApplication app_;

        public AccessTokenAcquirer(string clientId, StoreLocation certStoreLocation, StoreName certStoreName, string certificateCredentialId)
        {
            if (String.IsNullOrWhiteSpace(clientId)) throw new ArgumentNullException(nameof(clientId));
            if (String.IsNullOrWhiteSpace(certificateCredentialId)) throw new ArgumentNullException(nameof(certificateCredentialId));

            ClientId = clientId;
            CertificateCredentialIdentifier = certificateCredentialId;
            location_ = certStoreLocation;
            storeName_ = certStoreName;
            app_ = null;
        }

        public string CertificateCredentialIdentifier { get; private set; }
        
        public string ClientId { get; private set; }

        private void InstantiateConfidentialClient(string tenantId)
        {
            if (app_ != null) return;

            app_ = ConfidentialClientApplicationBuilder
                .Create(ClientId)
                .WithClientAssertion(GetClientCredentialAssertion(tenantId))
                .WithAuthority(AzureCloudInstance.AzurePublic, tenantId, validateAuthority: true)
                .Build();
        }

        private string GetClientCredentialAssertion(string tenantId)
        {
            using (var store = new X509Store(storeName_, location_, OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly))
            {
                X509Certificate2 clientCert = null;

                foreach (var enumeratedCert in store.Certificates)
                {
                    if (StringComparer.OrdinalIgnoreCase.Equals(CertificateCredentialIdentifier, enumeratedCert.Thumbprint))
                    { 
                        clientCert = enumeratedCert;
                        break;
                    }
                }

                if (clientCert == null)
                {
                    Console.WriteLine($"could not find a match for {CertificateCredentialIdentifier} in {location_}/{storeName_}; exiting..");
                    throw new ArgumentException("could not find a match for certificate {0}", CertificateCredentialIdentifier);
                }

                // prepare the claims for the self-signed token
                string aud = $"https://login.microsoftonline.com/{tenantId}/v2.0";
                var claims = new Dictionary<string, object>
                {
                    { "aud", aud },
                    { "iss", ClientId },
                    { "sub", ClientId },
                    { "jti", Guid.NewGuid().ToString() },
                };

                var tokenDescriptor = new SecurityTokenDescriptor
                {
                    Claims = claims,
                    SigningCredentials = new X509SigningCredentials(clientCert)
                };

                return new JsonWebTokenHandler().CreateToken(tokenDescriptor);
            }
        }

        public async Task<AuthenticationResult> AcquireTokenAsync(string tenantId, string audience)
        {
            InstantiateConfidentialClient(tenantId);

            var account = app_.GetAccountAsync(ClientId)
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();
            var scopes = new List<string>() { audience };
            AuthenticationResult authResult = null;

            try
            {
                // go for the cache
                authResult = app_.AcquireTokenSilent(scopes, account)
                    .ExecuteAsync()
                    .ConfigureAwait(false)
                    .GetAwaiter()
                    .GetResult();

                return authResult;
            }
            catch (MsalUiRequiredException ex)
            {
                Console.WriteLine($"silent token acquisition failed: {ex.GetType()}: {ex.ErrorCode}; falling back to interactive.");
            }

            try
            {
                authResult = await app_.AcquireTokenForClient(scopes)
                    .ExecuteAsync()
                    .ConfigureAwait(false);
            }
            catch (MsalClientException ex)
            {
                Console.WriteLine($"failed to acquire token for client: {ex.GetType()}: {ex.ErrorCode}; giving up.");
                throw;
            }

            return authResult;
        }

        public static string DisplayAuthenticationResult(AuthenticationResult authResult)
        {
            if (authResult == null) throw new ArgumentNullException(nameof(authResult));

            var builder = new StringBuilder();
            builder.AppendLine("\n");
            builder.AppendLine($"\tAccount: {authResult.Account}");
            builder.AppendLine($"\tAccess token: {authResult.AccessToken}");
            builder.AppendLine($"\ttoken provider: {authResult.AuthenticationResultMetadata.TokenSource}");
            builder.AppendLine($"\tAcquisition time (ms): {authResult.AuthenticationResultMetadata.DurationTotalInMs}");
            builder.AppendLine($"\tExpiresOn: {authResult.ExpiresOn}");
            builder.AppendLine($"\tExtendedExpiresOn: {authResult.ExtendedExpiresOn}");
            builder.AppendLine($"\tIdToken: {authResult.IdToken}");
            builder.AppendLine($"\tScopes: {String.Join(',', authResult.Scopes)}");
            builder.AppendLine($"\tTenantId: {authResult.TenantId}");

            return builder.ToString();
        }
    }
}
