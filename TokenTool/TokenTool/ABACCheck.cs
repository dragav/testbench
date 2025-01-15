namespace TokenTool
{
    using System;
    using Azure.Identity;
    using Microsoft.Graph;
    using System.Threading.Tasks;
    using Azure.Core;
    using System.Security.Cryptography.X509Certificates;
    using System.IdentityModel.Tokens.Jwt;
    using System.Text;

    public class ABACChecker
    {
        private static GraphServiceClient _graphClient;// = InstantiateGraphClient();

        public static void Initialize(Config config)
        {
            if (_graphClient == null)
            {
                _graphClient = new GraphServiceClient(
                    WithX509Credential(config.ClientId, config.TenantId, config.ClientPemPath),
                    ["https://graph.microsoft.us/.default"],
                    "https://graph.microsoft.us/v1.0");
            }
        }

        public static bool CheckAccess(string principalId, string resource, string action, AccessPolicy[] policies, out AccessPolicy firstMatchingPolicy)
        {
            ArgumentException.ThrowIfNullOrWhiteSpace(principalId);
            ArgumentException.ThrowIfNullOrWhiteSpace(resource);
            ArgumentException.ThrowIfNullOrWhiteSpace(action);
            ArgumentNullException.ThrowIfNull(policies);

            firstMatchingPolicy = null;

            var attributes = RetrieveAttributesForPrincipal(principalId);
            if (attributes == null)
            {
                Console.WriteLine($"no custom security attributes were assigned to {principalId}; access denied.");
                return false;
            }
            else
            {
                StringBuilder sb = new StringBuilder();
                foreach (var attr in attributes)
                {
                    sb.Append($"{attr.Name}: ");
                    foreach (var val in attr.Values)
                    {
                        sb.Append($"{val}, ");
                    }
                    _ = sb.Append("\t");
                }
                Console.WriteLine($"successfully retrieved custom security attributes for {principalId}: {sb.ToString()}");
            }

            // Check if the user has the required attributes for the resource and action
            foreach (var policy in policies)
            {
                if (policy.Resource != resource || policy.Action != action)
                {
                    continue;
                }

                if (policy.IsMatch(resource, action, attributes))
                {
                    firstMatchingPolicy = policy;
                    return true;
                }
            }

            return false;
        }

        private static AttributeAssignmentItem[] RetrieveAttributesForPrincipal(string principalId)
        {
            var graphResult = Task.Run(
                async() => await _graphClient.Users[principalId].GetAsync((requestConfiguration) =>
                            {
                                requestConfiguration.QueryParameters.Select = ["CustomSecurityAttributes"];
                            }))
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();
            Console.WriteLine($"successfully obtained CSAs for token subject");

            if (graphResult.CustomSecurityAttributes == null)
            {
                Console.WriteLine("no custom security attributes found");
                return null;
            }

            return AttributeAssignmentItem.FromGraphResult(graphResult.CustomSecurityAttributes);
        }

        public static TokenCredential WithX509Credential(string clientId, string tenantId, string x5path)
        {
            var clientCertificate = X509Certificate2.CreateFromPemFile(x5path);
            // https://learn.microsoft.com/dotnet/api/azure.identity.clientcertificatecredential
            return new ClientCertificateCredential(
                tenantId, 
                clientId, 
                clientCertificate, 
                new ClientCertificateCredentialOptions
                {
                    AuthorityHost = AzureAuthorityHosts.AzureGovernment,
                });
        }

        public static TokenCredential WithInteractiveBrowserCredential(string clientId, string tenantId)
        {
            var options = new InteractiveBrowserCredentialOptions
            {
                TenantId = tenantId,
                ClientId = clientId,
                AuthorityHost = AzureAuthorityHosts.AzureGovernment,
                // MUST be http://localhost or http://localhost:PORT
                // See https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/System-Browser-on-.Net-Core
                RedirectUri = new Uri("http://localhost"),
            };
            Console.WriteLine("Created InteractiveBrowserCredentialOptions");

            // https://learn.microsoft.com/dotnet/api/azure.identity.interactivebrowsercredential
            return new InteractiveBrowserCredential(options);
        }

        public static TokenCredential WithDeviceCodeCredential(string clientId, string tenantId)
        {
            var options = new DeviceCodeCredentialOptions
            {
                AuthorityHost = AzureAuthorityHosts.AzureGovernment,
                ClientId = clientId,
                TenantId = tenantId,
                // Callback function that receives the user prompt
                // Prompt contains the generated device code that user must
                // enter during the auth process in the browser
                DeviceCodeCallback = (code, cancellation) =>
                {
                    Console.WriteLine(code.Message);
                    return Task.FromResult(0);
                },
            };
            Console.WriteLine("Created DeviceCodeCredentialOptions");

            // https://learn.microsoft.com/dotnet/api/azure.identity.devicecodecredential
            return new DeviceCodeCredential(options);
        }
    }
}