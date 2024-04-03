namespace CertExplorer
{
    using Microsoft.IdentityModel.Tokens;
    using Newtonsoft.Json.Linq;
    using System;
    using System.Collections;
    using System.Collections.Generic;
    using System.IdentityModel.Tokens.Jwt;
    using System.IO;
    using System.Linq;
    using System.Security.Cryptography.X509Certificates;

    class Program
    {
        public static string CustomIssuerValidator(string issuer, SecurityToken securityToken, TokenValidationParameters validationParameters)
        {
            ;

            return String.Empty;
        }

        static void Main(string[] args)
        {
            if (Arguments.TryParse(args, out Arguments parsedArgs))
            {
                ProcessArguments(parsedArgs);

                return;
            }

            var command = parsedArgs == null ? nameof(Actions.Help) : parsedArgs.ParsedCommand;
            Console.WriteLine(Arguments.GetCommandHelp(command));

            return;
        }

        private static void ProcessArguments(Arguments args)
        {
            if (args.ParsedCommand.Equals(nameof(Actions.Help), StringComparison.InvariantCultureIgnoreCase))
            {
                var helpOnCommand = args.ParsedArgsForCommand == null ? args.ParsedCommand : args.ParsedArgsForCommand.Keys.First();
                Console.WriteLine(Arguments.GetCommandHelp(helpOnCommand));

                return;
            }

            if (!actionMap.ContainsKey(args.ParsedCommand))
            {
                Console.WriteLine($"Command '{args.ParsedCommand}' is not currently implemented.");

                return;
            }

            try
            {
                var handler = actionMap[args.ParsedCommand];
                var config = handler.Item1(args);

                handler.Item2(config);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"failed to process command '{args.ParsedCommand}': {ex.Message}");
            }
        }

        #region Action-specific argument parsing and validating
        private static ProbeConfig ProbingArgsToConfig(Arguments args)
        {
            var hasEndptParams = args.ParsedArgsForCommand.ContainsKey(nameof(Params.Endpoint))
                && args.ParsedArgsForCommand.ContainsKey(nameof(Params.Ports));

            var hasInventoryParams = args.ParsedArgsForCommand.ContainsKey(nameof(Params.FindType))
                && args.ParsedArgsForCommand.ContainsKey(nameof(Params.FindValue))
                && args.ParsedArgsForCommand.ContainsKey(nameof(Params.StoreName));

            var hasFreqParam = args.ParsedArgsForCommand.ContainsKey(nameof(Params.Interval));

            if ((!hasEndptParams && !hasInventoryParams)
                || !hasFreqParam)
            {
                throw new ArgumentException($"probing must specify at least one parameter set (endpoint or lookup) and an interval; see 'help probe'");
            }

            var interval = Int32.Parse(args.ParsedArgsForCommand[nameof(Params.Interval)]);
            string portsStr = null, serverUri = null;
            string findType = null, findValue = null, storeName = null;

            if (hasEndptParams)
            {
                portsStr = args.ParsedArgsForCommand[nameof(Params.Ports)];
                serverUri = args.ParsedArgsForCommand[nameof(Params.Endpoint)];
            }

            if (hasInventoryParams)
            {
                var allowedFindTypes = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
                { "TP", "CN", nameof(X509FindType.FindByThumbprint), nameof(X509FindType.FindBySubjectName) };

                findType = args.ParsedArgsForCommand[nameof(Params.FindType)];
                if (!allowedFindTypes.Contains(findType))
                    throw new ArgumentException($"allowed values for 'findType' are: {(string.Join(",", allowedFindTypes))}");
                if (findType.Equals("TP", StringComparison.InvariantCultureIgnoreCase))
                    findType = nameof(X509FindType.FindByThumbprint);
                else if (findType.Equals("CN", StringComparison.InvariantCultureIgnoreCase))
                    findType = nameof(X509FindType.FindBySubjectName);

                findValue = args.ParsedArgsForCommand[nameof(Params.FindValue)];
                storeName = args.ParsedArgsForCommand[nameof(Params.StoreName)];
            }

            return new ProbeConfig(portsStr)
            {
                LogLevel = LogLevel.Info,
                ServerUri = serverUri,
                TimerInterval = interval,
                FindType = findType,
                FindValue = findValue,
                StoreName = storeName
            };
        }

        private static CertExplorerConfig FindingArgsToConfig(Arguments args)
        {
            var hasInventoryParams = args.ParsedArgsForCommand.ContainsKey(nameof(Params.FindType))
                && args.ParsedArgsForCommand.ContainsKey(nameof(Params.FindValue))
                && args.ParsedArgsForCommand.ContainsKey(nameof(Params.StoreName));

            if (!hasInventoryParams)
            {
                throw new ArgumentException($"finding must specify all lookup parameters; see 'help find'");
            }

            var findType = args.ParsedArgsForCommand[nameof(Params.FindType)];
            var allowedFindTypes = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
                { "TP", "CN", nameof(X509FindType.FindByThumbprint), nameof(X509FindType.FindBySubjectName) };
            if (!allowedFindTypes.Contains(findType))
                throw new ArgumentException($"allowed values for 'findType' are: {(string.Join(",", allowedFindTypes))}");

            var findValue = args.ParsedArgsForCommand[nameof(Params.FindValue)];
            var storeName = args.ParsedArgsForCommand[nameof(Params.StoreName)];

            return new CertExplorerConfig()
            {
                LogLevel = LogLevel.Info,
                FindType = findType,
                FindValue = findValue,
                StoreName = storeName
            };
        }

        private static IssuerValidationConfig IssuerArgsToConfig(Arguments args)
        {
            var hasEndptParams = args.ParsedArgsForCommand.ContainsKey(nameof(Params.Endpoint))
                && args.ParsedArgsForCommand.ContainsKey(nameof(Params.Ports));

            var hasIssuerParams = args.ParsedArgsForCommand.ContainsKey(nameof(Params.IssuerSource))
                && args.ParsedArgsForCommand.ContainsKey(nameof(Params.IssuerVal));

            var hasExpectedCN = args.ParsedArgsForCommand.ContainsKey(nameof(Params.FindValue));

            if (!hasEndptParams 
                || !hasIssuerParams)
            {
                throw new ArgumentException($"issuer validation must specify at least the endpoint, port, issuer source and value; see 'help validateIssuer'");
            }

            string portsStr = args.ParsedArgsForCommand[nameof(Params.Ports)];
            string serverUri = args.ParsedArgsForCommand[nameof(Params.Endpoint)];
            string issuerSrc = args.ParsedArgsForCommand[nameof(Params.IssuerSource)];
            string issuerVal = args.ParsedArgsForCommand[nameof(Params.IssuerVal)];
            string findValue = null;
            if (hasExpectedCN) findValue = args.ParsedArgsForCommand[nameof(Params.FindValue)];

            return new IssuerValidationConfig(portsStr)
            {
                ServerUri = serverUri,
                FindValue = findValue,
                IssuerSource = issuerSrc,
                IssuerValue = issuerVal
            };
        }

        private static IssuerRetrievalConfig GetIssuerArgsToConfig(Arguments args)
        {
            var hasEndptParams = args.ParsedArgsForCommand.ContainsKey(nameof(Params.Endpoint))
                && args.ParsedArgsForCommand.ContainsKey(nameof(Params.Ports));

            var hasIssuerParams = args.ParsedArgsForCommand.ContainsKey(nameof(Params.IssuerSource))
                && args.ParsedArgsForCommand.ContainsKey(nameof(Params.IssuerVal));

            var hasExpectedCN = args.ParsedArgsForCommand.ContainsKey(nameof(Params.FindValue));

            string issuerUri = string.Empty;
            if (args.ParsedArgsForCommand.ContainsKey(nameof(Params.IssuerVal)))
            {
                issuerUri = args.ParsedArgsForCommand[nameof(Params.IssuerVal)];
            }

            return new IssuerRetrievalConfig()
            {
                IssuerValue = issuerUri
            };
        }
        #endregion

        delegate void CommandHandler(Config config);
        delegate Config ConfigBuilder(Arguments args);

        private static Dictionary<string, Tuple<ConfigBuilder, CommandHandler>> actionMap = new Dictionary<string, Tuple<ConfigBuilder, CommandHandler>>(StringComparer.InvariantCultureIgnoreCase)
        {
            { nameof(Actions.Probe), new Tuple<ConfigBuilder, CommandHandler>(ProbingArgsToConfig, DoProbe) },
            { nameof(Actions.Find), new Tuple<ConfigBuilder, CommandHandler>(FindingArgsToConfig, DoFind) },
            { nameof(Actions.List), new Tuple<ConfigBuilder, CommandHandler>(FindingArgsToConfig, DoList) },
            { nameof(Actions.ValidateIssuer), new Tuple<ConfigBuilder, CommandHandler>(IssuerArgsToConfig, DoValidateIssuer) },
            { nameof(Actions.GetIssuers), new Tuple<ConfigBuilder, CommandHandler>(GetIssuerArgsToConfig, DoGetIssuers) },
        };

        #region Action-specific handlers
        private static void DoProbe(Config probeConfig)
        {
            var ts = DateTime.UtcNow.ToString("u").Replace(':', ' ').Replace('-', ' ').Replace(" ", "");
            var logFileName = Directory.GetCurrentDirectory() + "\\CertificateProbe-" + ts + ".log";
            var typedConfig = probeConfig as ProbeConfig;
            if (typedConfig == null) throw new ArgumentException($"{nameof(probeConfig)} is not of expected ProbeConfig type");

            using (var probe = new CertificateProbe(typedConfig, logFileName))
            { 
                probe.EndlessRun();
            }

            //localCertStoreName: "my",
            //localCertFindType: X509FindType.FindBySubjectName,
            //localCertFindValue: "WinFabric-Test-SAN1-Alice",
            //serverUri: "sftestinfra-dev3.westus.cloudapp.azure.com",
            //port: 19080,
            //TimeSpan.FromSeconds(10.0),
            //logFileName))
        }

        private static void DoFind(Config probeConfig)
        { }

        private static void DoList(Config probeConfig)
        { }

        private static void DoValidateIssuer(Config issuerConfig)
        {
            var typedConfig = issuerConfig as IssuerValidationConfig;
            if (typedConfig == null) throw new ArgumentException($"{nameof(issuerConfig)} is not of expected IssuerValidationConfig type");

            bool result;
            using (var serverPoker = new ServerCertExplorer(typedConfig.ServerUri, typedConfig.Ports[0], new Logger()))
            {
                try
                {
                    result = serverPoker.ValidateIssuer(typedConfig);
                }
                catch (Exception)
                {
                    result = false;
                }
            }

            var status = result ? "succeeded" : "failed";
            Console.WriteLine($"certificate issuer validation for endpoint '{typedConfig.ServerUri}:{typedConfig.Ports[0]}' against subject '{typedConfig.FindValue?? "(n/a)"}' and authorized issuers from '{typedConfig.IssuerValue}' {status}.");
        }

        private static void DoGetIssuers(Config issuerRetrievalConfig)
        {
            var typedConfig = issuerRetrievalConfig as IssuerRetrievalConfig;
            if (typedConfig == null) throw new ArgumentException($"{nameof(issuerRetrievalConfig)} is not of expected IssuerRetrievalConfig type");

            bool result;
            using (var issuerRetriever = new AutoIssuers(typedConfig.IssuerValue, new Logger()))
            {
                try
                {
                    issuerRetriever.Run();
                    result = true;
                }
                catch (Exception)
                {
                    result = false;
                }
            }

            var status = result ? "succeeded" : "failed";
            Console.WriteLine($"attempting to retrieve certificate issuers from '{typedConfig.IssuerValue}' {status}.");
        }
        #endregion

        private static void ListEnvVars()
        {
            Console.WriteLine("\n\n====== env vars ==============");
            foreach (DictionaryEntry entry in Environment.GetEnvironmentVariables())
            {
                Console.WriteLine("  {0} = {1}", entry.Key, entry.Value);
            }
        }

        #region history of invocations

        //var tp = "7812205A39D22376DAA037F05AEDE3601A7E64BF";
        //X509Certificate2Collection certs = null;
        //certs = CertExplorer.FindMatchingCertificates(
        //    StoreLocation.LocalMachine, 
        //    StoreName.My, 
        //    X509FindType.FindByThumbprint, 
        //    tp, 
        //    String.Empty, 
        //    doTakeMostRecentOnly: true, 
        //    excludeExpiredCerts: false);
        //string linkedTP =  CertExplorer.GetCertificateContextProperty(certs[0], 64);
        //CertExplorer.TestCertificateValidation();
        //var results = SecurityConfigGenerator.GenerateConfigurations();
        //foreach (var entry in results)
        //{
        //    Console.WriteLine($"{entry}");
        //}

        //foreach (var entry in results)
        //{
        //    Console.WriteLine($"{entry.ToShortString()}");
        //}
        //var ext = Path.GetExtension(null);
        //ext = Path.GetExtension(String.Empty);
        //X509CertificateEnumerator.ListFromDirectory(X509CertificateEnumerator.LinuxCertStorePath);
        //X509Certificate2Collection certs = null;
        //certs = CertExplorer.FindMatchingCertificates(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindByThumbprint, "5e4a0ac68604f17a406012093218f524dba8d162", String.Empty, doTakeMostRecentOnly: true, excludeExpiredCerts: false);
        //CertExplorer.TestCertificateValidation();

        //if ((args.Length < 2)
        //    || !args[0].Equals("-find")
        //    || String.IsNullOrWhiteSpace(args[1]))
        //{
        //    // use locally defined certs
        //    List<string> localCerts = new List<string> {
        //    "FBBFA23AD2ABDE1017DE526379200700346687F1",
        //    "E7EDB688F5EC3941B59578FC288E9CA13A6C796C",
        //    "D5EC423B79CBE507FD83593C56B9D53124254264",
        //    "CC719792BB3D14B74C67DBD913D637E3DA5F1984",
        //    "CA16CB7965509E169DC68C4DA3EB5D39FCA8CD9B",
        //    "C8F2BDF4EDC79D6B2D9747C2AEE193A665CED4B7",
        //    "C750A0612F9F1A4197F05C154FFE3CD52AC2123E",
        //    "C43C3DD54B19CF80635212D75DFCA32EAB7607BB",
        //    "C2A92DD7764004BC906B87974F4186E5F9064112",
        //    "BC21AE9F0B88CF6EA9B4D6233F972A6063B225A9",
        //    "B22B3D4CFED5FACC5A41DB9FC95AFF9633F349AF",
        //    "ADFC919713168D9FA8EE712BA2F437620003490D",
        //    "A463054E32ACCBC0F6AF0B10255CB97639AFADE9",
        //    "9F1B740D5AFC49EBCDA962DDEF65BC05B9572A7C",
        //    "9DC906B169DC4FAFFD1697AC781E806790749D2F",
        //    "9C543333041ACF9B36211FA1978B3FEFC9F03FFE",
        //    "9010DE1097AFD7F45B24385DDA1B3FC0786B80A0",
        //    "8EC3C1EC58C205871B921C5DBBA809E63D1A32CF",
        //    "8E8BD22EDF44FA073093FEDAA9500B383555F682",
        //    "8C1A483A49E19DFF90199CB862148D859F998612",
        //    "8890C0ABBF45F4528A6A3E6B709F76B09428AA74",
        //    "87D9B9B107327DF412930FBFC13893F00F4F072F",
        //    "85469332971A85B8F382B7795A17CC0EE575DF6F",
        //    "7812205A39D22376DAA037F05AEDE3601A7E64BF",
        //    "6F4AA9618AEA95AB5DCE8C77260938653EE15FD7",
        //    "5FDF1116B15EE687CB14C7AE3D67B166AAD64F80",
        //    "5E4A0AC68604F17A406012093218F524DBA8D162",
        //    "59EC792004C56225DD6691132C713194D28098F1",
        //    "5269237DAFE7CA884A54BC059981965C1B8ADD1C",
        //    "4FEF3950642138446CC364A396E1E881DB76B48C",
        //    "4C1C6BFC2911B3973FEEAD8A8EE0E3A4E35F582A",
        //    "445745AB6F275CCB2A50641BCC0F63F0BF5E476F",
        //    "416E15A1B238DED37C0BF1F0877E25EB986E4515",
        //    "3CC9671C7A3E011857B73858BC11198F1D45C3D6",
        //    "2DA3223CDD1945BFFB443FB392665F43227E3516",
        //    "2A52AA7E00F1355D4851C435D619D5F6E71E9025",
        //    "1D70E39FEA57E6B0982A5988ED8482F86B5D2C9E",
        //    "1CA02F96CDFA3AFAB39E41475281C9F5BF558286",
        //    "0CD6DC96A67993D68843F1657741D25E3394B6C0" };

        //    certs = new X509Certificate2Collection();
        //    foreach (var tp in localCerts)
        //    {
        //        certs.AddRange(CertExplorer.FindMatchingCertificates(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindByThumbprint, tp, String.Empty, doTakeMostRecentOnly: true, excludeExpiredCerts: false));
        //    }
        //}
        //else if (args.Length == 2)
        //{
        //    // user-provided arguments
        //    certs = CertExplorer.FindMatchingCertificates(StoreLocation.LocalMachine, StoreName.My, X509FindType.FindByThumbprint, args[1], String.Empty, doTakeMostRecentOnly: true, excludeExpiredCerts: false);
        //}
        //else
        //{
        //    throw new ArgumentException("usage: CertExplorer -find {x509FindValue}");
        //}

        //List<string> issuers = new List<string> {
        //    "1b45ec255e0668375043ed5fe78a09ff1655844d",
        //    "d7fe717b5ff3593764f4d90654d86e8362ec26c8",
        //    "3ac7c3cac8de0dd392c02789c8be97474f456960",
        //    "96ea05926e2e42cc207e358668be2c316857fb5e" };

        //Console.WriteLine("=============================");
        //foreach (var cert in certs)
        //{
        //    // var isValid = CertExplorer.TryValidateX509Certificate(cert, issuers);
        //    Console.Write($"validating cert '{cert.Thumbprint}' against thumbprint 'blahdiblah': ");
        //    var validated = CertExplorer.TryValidateCertificateByThumbprint(cert, "blahdiblah", false, out bool isValidCertificate, out X509ChainStatus[] chainStatus);
        //    Console.WriteLine($"isValid: {isValidCertificate}");

        //    // try a different validation
        //    Console.Write($"validating cert '{cert.Thumbprint}' against its own thumbprint (accept expired):");
        //    validated = CertExplorer.TryValidateCertificateByThumbprint(cert, cert.Thumbprint.ToLowerInvariant(), true, out isValidCertificate, out chainStatus);
        //    Console.WriteLine($"isValid: {isValidCertificate}");
        //}

        //CertExplorer.SetAccessRuleForMatchingCertificates(
        //    StoreLocation.LocalMachine,
        //    StoreName.My,
        //    X509FindType.FindBySubjectName,
        //    "WinFabric-Test-SAN1-Alice",
        //    //"NC encryption cert",
        //    "NT AUTHORITY\\NETWORK SERVICE",
        //    CryptoKeyRights.GenericExecute | CryptoKeyRights.GenericRead);

        //CertExplorer.TestCertificateRetrieval();
        //CertExplorer.FindMatchingCertificates(StoreName.My, StoreLocation.CurrentUser, args[1]);
        //ListEnvVars();

        //var certList = CertExplorer.ListCertificates();
        //foreach(var certTp in certList)
        //{
        //    Console.WriteLine("* {0}", certTp);
        //}

        //CertExplorer.DumpCertificateProperties("B90A554DD29AD2F6DA3F5ADFB367738053F984C3");
        //CertExplorer.DumpCertificateProperties("C2A92DD7764004BC906B87974F4186E5F9064112");

        #endregion
    }
}
