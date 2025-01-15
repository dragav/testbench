namespace TokenTool
{
    using System;
    using System.Collections.Generic;
    using System.Threading;
    using System.Threading.Tasks;
    using Azure.Core;
    using Microsoft.Kiota.Abstractions.Serialization;
    
    class Program
    {
        static readonly HashSet<string> keys_ = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
            {
                "clientid",
                "tenantid",
                "clienttp",
                "aud",
                "sendx5c",
                "clientpempath",
                "principalid"
            };

        static readonly char slash_ = '/';
        static readonly char equal_ = '=';

        static void Main(string[] args)
        {
            var config = ParseArguments(args);
            Console.WriteLine($"running with config: clientId = {config.ClientId}, tenantId = {config.TenantId}, clientTP = {config.ClientCredentialTP}, aud = {config.TokenAudience}, sendX5c = {config.SendX5c}, clientPemPath = {config.ClientPemPath}, principalId = {config.PrincipalId}");

            Console.WriteLine($"attempting to instantiate Graph client for clientid {config.ClientId} and tenant {config.TenantId}");
            ABACChecker.Initialize(config);

            var policies = new AccessPolicy[]
            {
                AccessPolicy.HybridAccessPolicy,
                AccessPolicy.CrescoBinAccessPolicy,
                AccessPolicy.MimcoAccessPolicy,
                AccessPolicy.HyenaAccessPolicy
            };
            Console.WriteLine($"evaluating {config.PrincipalId} against the following policies:");
            foreach (var policy in policies)
            {
                Console.WriteLine($"\t{policy.ToString()}");
            }

            if (ABACChecker.CheckAccess(config.PrincipalId, policies[0].Resource, policies[0].Action, policies, out var matchingPolicy))
            {
                Console.WriteLine($"access granted to {config.PrincipalId} for policy {matchingPolicy.Name} for {matchingPolicy.Resource}/{matchingPolicy.Action}");
            }
            else
            {
                Console.WriteLine($"no policy matched for token.");
            }
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
                SendX5c = parsedArgs.ContainsKey("sendx5c") ? bool.Parse(parsedArgs["sendx5c"]) : false,
                ClientPemPath = parsedArgs.ContainsKey("clientpempath") ? parsedArgs["clientpempath"] : "",
                PrincipalId = parsedArgs.ContainsKey("principalid") ? parsedArgs["principalid"] : ""
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
