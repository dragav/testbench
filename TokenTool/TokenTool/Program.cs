namespace TokenTool
{
    using System;
    using System.Collections.Generic;
    using System.Security.Cryptography.X509Certificates;

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
            var parsedArgs = ParseArguments(args);
            var result = TryAcquireToken(parsedArgs["clientid"], parsedArgs["clienttp"], parsedArgs["tenantid"], parsedArgs["aud"], bool.Parse(parsedArgs["sendx5c"]));
            Console.WriteLine("token acquisition {0}.", result ? "succeeded" : "failed");

            return;
        }

        private static Dictionary<string, string> ParseArguments(string[] args)
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
            return parsedArgs;
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

        private static bool TryAcquireToken(string clientId, string clientCredentialTP, string tenantId, string tokenAudience, bool sendX5c)
        {
            var result = false;
            try
            {
                var acquirer = new AccessTokenAcquirer(
                    clientId,
                    StoreLocation.CurrentUser,
                    StoreName.My,
                    clientCredentialTP);

                var authResult = acquirer.AcquireTokenAsync(tenantId, tokenAudience, sendX5c)
                    .ConfigureAwait(false)
                    .GetAwaiter()
                    .GetResult();

                Console.WriteLine($"successfully obtained a token for {tokenAudience}; result: {AccessTokenAcquirer.DisplayAuthenticationResult(authResult)}");
                result = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"exception of type {ex.GetType()} encountered: {ex.Message}");
            }

            return result;
        }
    }
}
