namespace TokenTool
{
    using System;
    using Azure.Identity;
    using Microsoft.Graph;
    using System.Threading.Tasks;

    public class ABACChecker
    {
        private static readonly GraphServiceClient _graphClient;// = InstantiateGraphClient();

        public static bool CheckAccess(string token, string resource, string action, AccessPolicy[] policies, out AccessPolicy firstMatchingPolicy)
        {
            if (String.IsNullOrEmpty(token)) throw new ArgumentException(nameof(token));
            if (String.IsNullOrEmpty(resource)) throw new ArgumentException(nameof(resource));
            if (String.IsNullOrEmpty(action)) throw new ArgumentException(nameof(action));
            if (policies == null) throw new ArgumentException(nameof(policies));

            firstMatchingPolicy = null;

            // Check if the token is valid
            // if (!TokenValidator.ValidateToken(token, out var claims))
            // {
            //     firstMatchingPolicy = null;
            //     return false;
            // }

            // Get the user's attributes from the token
            // var attributes = RetrieveAttributesForPrincipal(claims);

            // // Check if the user has the required attributes for the resource and action
            // foreach (var policy in policies)
            // {
            //     if (policy.Resource != resource || policy.Action != action)
            //     {
            //         continue;
            //     }

            //     foreach (var requiredAttribute in policy.RequiredAttributes)
            //     {
            //         foreach (var actualAttribute in attributes)
            //         {
            //             if (requiredAttribute.Set == actualAttribute.Set &&
            //                 requiredAttribute.Name == actualAttribute.Name &&
            //                 requiredAttribute.Values.Intersect(actualAttribute.Values).Any())
            //             {
            //                 firstMatchingPolicy = policy;
            //                 return true;
            //             }
            //         }
            //     }
            // }

            firstMatchingPolicy = null;
            return false;
        }

        private static AttributeAssignmentItem[] RetrieveAttributesForPrincipal(string[] claims)
        {
            // Retrieve the user's attributes from the claims
            var attributes = new AttributeAssignmentItem[] {};
            int idx = 0;
            foreach (var claim in claims)
            {
                attributes[idx++] = new AttributeAssignmentItem
                {
                    Set = AttributeSets.AMLAccess.ToString(),
                    Name = claim,
                    AllowMultiple = true,
                    Values = new string[] { claim }
                };
            }

            return attributes;
        }

        private static IAuthenticationProvider WithX509Credential(string clientId, string tenantId, string x5path)
        {
            var scopes = new[] { "https://graph.microsoft.com/.default" };

            using (var clientCertificate = new X509Certificate2(x5path))
            {
                // https://learn.microsoft.com/dotnet/api/azure.identity.clientcertificatecredential
                return new ClientCertificateCredential(
                    tenantId, 
                    clientId, 
                    clientCertificate, 
                    new ClientCertificateCredentialOptions
                    {
                        AuthorityHost = AzureAuthorityHosts.AzureGovernment,
                        RedirectUri = new Uri("http://localhost"),
                    });
            }
        }

        private static IAuthenticationProvider WithInteractive

        public static GraphServiceClient InstantiateGraphClient(string clientId, string tenantId)
        {

            // // Create the authentication provider
            // var authProvider = new AzureIdentityAuthenticationProvider(
            //     credential,
            //     isCaeEnabled: true,
            //     scopes: scopes);

            // Create the Microsoft Graph client object using
            // the Microsoft Graph for US Government L4 endpoint
            // NOTE: The API version must be included in the URL
            var graphClient = new GraphServiceClient(
                credential,
                scopes);
                //"https://graph.microsoft.us/v1.0");

            // var options = new DeviceCodeCredentialOptions
            // {
            //     AuthorityHost = AzureAuthorityHosts.AzureGovernment,
            //     ClientId = clientId,
            //     TenantId = tenantId,
            //     // Callback function that receives the user prompt
            //     // Prompt contains the generated device code that user must
            //     // enter during the auth process in the browser
            //     DeviceCodeCallback = (code, cancellation) =>
            //     {
            //         Console.WriteLine(code.Message);
            //         return Task.FromResult(0);
            //     },
            // };
            // Console.WriteLine("Created DeviceCodeCredentialOptions");

            // // https://learn.microsoft.com/dotnet/api/azure.identity.devicecodecredential
            // var deviceCodeCredential = new DeviceCodeCredential(options);
            // Console.WriteLine("Created DeviceCodeCredential");
            //var graphClient = new GraphServiceClient(deviceCodeCredential, scopes);    

            Console.WriteLine("Created GraphServiceClient");
            return graphClient;
        }
    }
}