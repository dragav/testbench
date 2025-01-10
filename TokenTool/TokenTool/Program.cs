namespace TokenTool
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading.Tasks;

    class Program
    {
        static readonly HashSet<string> keys_ = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
            {
                "clientid",
                "tenantid",
                "clienttp",
                "aud",
                "sendx5c"
            };

        static readonly char slash_ = '/';
        static readonly char equal_ = '=';

        static void Main(string[] args)
        {
            var config = ParseArguments(args);
            Console.WriteLine($"running with config: clientId = {config.ClientId}, tenantId = {config.TenantId}, clientTP = {config.ClientCredentialTP}, aud = {config.TokenAudience}, sendX5c = {config.SendX5c}");
            //var result = TryAcquireToken(parsedArgs["clientid"], parsedArgs["clienttp"], parsedArgs["tenantid"], parsedArgs["aud"], bool.Parse(parsedArgs["sendx5c"]));
            var result = TryAcquireToken(config.ClientId, config.TokenAudience, "", config.TenantId, config.SendX5c);
            Console.WriteLine("token acquisition {0}.", result ? "succeeded" : "failed");

            return;
        }

        private static Config ParseArguments(string[] args)
        {
            if (args == null
                || args.Length == 0) 
                ThrowAndPrintHelp("(no arguments provided)");

            Dictionary<string, string> parsedArgs = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

            foreach (var entry in args)
            {
                // we expect an entry of the form: /<key>:<value>
                if (!entry.StartsWith(slash_)) ThrowAndPrintHelp(entry); // wrong separator
                var tokens = entry.Split(equal_, StringSplitOptions.RemoveEmptyEntries);
                if (tokens.Length != 2) ThrowAndPrintHelp(entry); // wrong format
                var key = tokens[0].Substring(1);
                var value = tokens[1];

                if (!keys_.Contains(key)) ThrowAndPrintHelp(entry); // unknown command
                if (parsedArgs.ContainsKey(key)) ThrowAndPrintHelp(entry); // repeat command

                parsedArgs[key] = value;
            }

            // add default for sendx5c option
            if (!parsedArgs.ContainsKey("sendx5c")) parsedArgs["sendx5c"] = "false";
            
            return new Config
            { 
                ClientId = parsedArgs.ContainsKey("clientid") ? parsedArgs["clientId"] : "037b9ea6-2276-4f21-80cc-af404bb0e00c",
                ClientCredentialTP = parsedArgs.ContainsKey("clienttp") ? parsedArgs["clienttp"] : "",
                TenantId = parsedArgs.ContainsKey("tenantid") ? parsedArgs["tenantid"] : "c7c74d3d-620e-4c8a-b565-c0c3a3061477",
                TokenAudience = parsedArgs.ContainsKey("aud") ? parsedArgs["aud"] : "c836cbdb-7a5b-44cc-a54f-564b4b486fc6", // throw new ArgumentException("audience is required"),
                SendX5c = parsedArgs.ContainsKey("sendx5c") ? bool.Parse(parsedArgs["sendx5c"]) : false
            };        
        }

        private static void PrintHelp()
        {
            Console.WriteLine("Usage: tokenTool /clientId=<cid> /tenantId=<tid> /clientTp=<client cred thumbprint> /aud=<resource> /sendX5c=<true|*false*>");
        }

        private static void ThrowAndPrintHelp(string argName)
        {
            PrintHelp();
            throw new ArgumentException(argName);
        }

        private static bool TryAcquireToken(
            string clientId, 
            string tokenAudience, 
            string clientCredentialTP = "", 
            string tenantId = "", 
            bool sendX5c = false)
        {
            Console.WriteLine($"attempting to instantiate Graph client for clientid {clientId} and tenant {tenantId}");
            var graphClient = ABACChecker.InstantiateGraphClient(clientId, tenantId);
            Console.WriteLine($"successfully instantiated Graph client for clientid {clientId} and tenant {tenantId}");

            var graphResult = Task.Run(
                async() => await graphClient.Users["{user-id}"].GetAsync((requestConfiguration) =>
                            {
                                requestConfiguration.QueryParameters.Select = new string []{ "customSecurityAttributes" };
                            }))
                .ConfigureAwait(false)
                .GetAwaiter()
                .GetResult();
            Console.WriteLine($"successfully obtained CSAs for {clientId}; result: {graphResult}");

            var result = false;
            // try
            // {
            //     var acquirer = new AccessTokenAcquirer(
            //         clientId,
            //         StoreLocation.CurrentUser,
            //         StoreName.My,
            //         clientCredentialTP);

            //     var authResult = acquirer.AcquireTokenAsync(tenantId, tokenAudience, sendX5c)
            //         .ConfigureAwait(false)
            //         .GetAwaiter()
            //         .GetResult();

            //     Console.WriteLine($"successfully obtained a token for {tokenAudience}; result: {AccessTokenAcquirer.DisplayAuthenticationResult(authResult)}");
            //     result = true;
            // }
            // catch (Exception ex)
            // {
            //     Console.WriteLine($"exception of type {ex.GetType()} encountered: {ex.Message}");
            // }

            return result;
        }
    }
}
