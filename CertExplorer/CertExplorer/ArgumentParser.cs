
namespace CertExplorer
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Actions (verbs) implemented.
    /// </summary>
    enum Actions
    {
        None,
        Help,
        List,
        Find,
        Validate,
        Dump,
        Acl,
        Probe,
        Link,
        ValidateIssuer,
        GetIssuers,
    };

    /// <summary>
    /// Set of all parameters, across actions.
    /// </summary>
    enum Params
    {
        FindType, 
        FindValue,
        StoreName,
        Interval,
        Ports,
        Endpoint,
        IssuerSource,
        IssuerVal
    };

    /// <summary>
    /// Class implementing the handling and parsing of command line arguments.
    /// </summary>
    public sealed class Arguments
    {
        /// <summary>
        /// Mapping of parameters to actions.
        /// </summary>
        private readonly Dictionary<string, Dictionary<string, string>> argMap_ = new Dictionary<string, Dictionary<string, string>>(StringComparer.InvariantCultureIgnoreCase);

        // help for help, or missing parameters
        private static readonly string helpHelp_ =
@"CertExplorer [command] [parameters]
    where commands are: 
        help
        probe
        find
        list
        validate
        validateIssuer
        getIssuers

Type 'CertExplorer help [command]' for command-specific usage.";

        // help for Probe action
        private static readonly string probeHelp_ =
@"CertExplorer probe [parameters]
    where supported parameters are:
        findType=<TP | CN>              // 'lookup' set
        findValue=<TP/CN value>         // 'lookup' set
        storeName=<store name>          // 'lookup' set
        endpoint=<server URI>           // 'probing' set
        ports=<port1, port2..>          // 'probing' set
        interval=<period in seconds>    // required

At least one of the 'lookup' or 'probing' parameter sets are required; all parameters of a set must be specified.

e.g.: 
    CertExplorer probe findType=CN findValue=alice.universalexports.com storeName=my interval=10 
    ---- lists contents of certificate store LocalMachine\my every 10s looking for certificates whose subject CN matches 'alice.universalexports.com'

    CertExplorer probe endpoint=sftestinfra-dev3.westus.cloudapp.azure.com ports=1026,19080 interval=5 
    ---- returns certificate info of the endpoint sftestinfra-dev3.westus.cloudapp.azure.com for each of the ports 1026, 19080 every 5 seconds

Lookup and endpoint probing can be combined in a single invocation; these will be separate timers running on the same schedule.";

        // help for Find action
        private static readonly string findHelp_ =
@"CertExplorer find [parameters]
    where required parameters are:
        findType=<TP | CN>          // 'lookup' set
        findValue=<TP/CN value>     // 'lookup' set
        storeName=<store name>      // 'lookup' set

All parameters must be specified.";

        // help for issuer validation
        private static readonly string validateIssuersHelp_ =
@"CertExplorer validateIssuer [parameters]
    where required parameters are:
        endpoint=<cluster management endpoint URI>       
        ports=<cluster management endpoint port>
        findValue=<cluster management server cert CN>
        issuerSource=<STR | URI>
        issuerVal=<value>

'issuerSource' refers to the predetermined list of issuer thumbprints authorized for this cluster's certificate;
    - STR: issuerVal contains the list of issuer TPs, provided as a comma-separated string in the command line 
    - URI: issuerVal is set to the GetIssuersV2 API invocation which returns the list of issuers

e.g.:
    CertExplorer validateIssuer endpoint=sftest.westus.cloudapp.azure.com ports=19080 findValue=alice.universalexports.com issuerSource=str issuerVal=8f1fd57f27c828d7be29743b4d02cd7e6e5f43e6,2f2877c5d778c31e0f29c7e371df5471bd673173
    ---- validates whether the server certificate presented by https://sftest.westus.cloudapp.azure.com:19080 matches CN=alice.universalexports.com and is issued by a CA with the SHA-1 TP of either 8f1fd57f27c828d7be29743b4d02cd7e6e5f43e6 or 2f2877c5d778c31e0f29c7e371df5471bd673173

    CertExplorer validateIssuer endpoint=sftest.westus.cloudapp.azure.com ports=19080 findValue=alice.universalexports.com issuerSource=uri issuerVal=https://issuer.pki.azure.com/dsms/issuercertificates?getissuersv2&appType=ssl
    ---- validates whether the server certificate presented by https://sftest.westus.cloudapp.azure.com:19080 matches CN=alice.universalexports.com and is issued by a CA returned by the invocation of the above GetIssuersV2 URI. Please specify a correct and appropriate URI, complete with parameters - appType, caName etc. For more information, please refer to http://aka.ms/getissuers.
";

        // help for issuer validation
        private static readonly string getIssuersHelp_ =
@"CertExplorer getIssuers [parameters]
    where required parameters are:
        issuerVal=<value>

issuerVal is the GetIssuersV2 API invocation which returns the list of issuers

e.g.:
    CertExplorer getIssuers issuerVal=https://issuer.pki.azure.com/dsms/issuercertificates?getissuersv2&appType=ssl
    ---- prints an ordered list of CAs returned by the invocation of the above GetIssuersV2 URI. Please specify a correct and appropriate URI, complete with parameters - appType, caName etc. For more information, please refer to http://aka.ms/getissuers.
";

        // help for specific actions
        private static readonly Dictionary<string, string> helpMap_ = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase)
        {
            { nameof(Actions.Help), helpHelp_ },
            { nameof(Actions.List), "(not implemented)" },
            { nameof(Actions.Find), findHelp_ },
            { nameof(Actions.Validate), "(not implemented)" },
            { nameof(Actions.Probe), probeHelp_ },
            { nameof(Actions.None), helpHelp_ },
            { nameof(Actions.ValidateIssuer), validateIssuersHelp_ },
            { nameof(Actions.GetIssuers), getIssuersHelp_ },
        };

        // expected params for cert lookup action
        private static readonly HashSet<string> certLookupParams_ = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
        {
            // all parameters are required
            nameof(Params.FindType),
            nameof(Params.FindValue),
            nameof(Params.StoreName)
        };

        // expected/supported params for probing action
        private static readonly HashSet<string> probingParams_ = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
        {
            // either of endpoint+ports or find* are required
            nameof(Params.FindType),
            nameof(Params.FindValue),
            nameof(Params.StoreName),
            nameof(Params.Interval),
            nameof(Params.Endpoint),
            nameof(Params.Ports)
        };

        // extended help supported for specific actions
        private static readonly HashSet<string> helpParams_ = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
        {
            nameof(Actions.List),
            nameof(Actions.Find),
            nameof(Actions.Validate),
            nameof(Actions.Probe),
            nameof(Actions.ValidateIssuer)
        };

        // expected params for issuer validation action
        private static readonly HashSet<string> validateIssuerParams_ = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
        {
            nameof(Params.Endpoint),
            nameof(Params.Ports),
            nameof(Params.IssuerSource),
            nameof(Params.IssuerVal),
            nameof(Params.FindValue)
        };

        // expected params for issuer validation action
        private static readonly HashSet<string> getIssuerParams_ = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase)
        {
            nameof(Params.IssuerVal)
        };

        // dummy/no param object
        private static readonly HashSet<string> noParams_ = new HashSet<string>(StringComparer.InvariantCultureIgnoreCase) { };

        // mapping of parameters to actions
        private static readonly Dictionary<string, HashSet<string>> commandParams_ = new Dictionary<string, HashSet<string>>(StringComparer.InvariantCultureIgnoreCase)
        {
            { nameof(Actions.Help), helpParams_ },
            { nameof(Actions.List), certLookupParams_ },
            { nameof(Actions.Find), certLookupParams_ },
            { nameof(Actions.Validate), noParams_ },
            { nameof(Actions.Probe), probingParams_ },
            { nameof(Actions.None), noParams_ },
            { nameof(Actions.ValidateIssuer), validateIssuerParams_ },
            { nameof(Actions.GetIssuers), getIssuerParams_ },
        };

        public Arguments(string[] args)
        {
            ArgsStr = args;
        }

        public string[] ArgsStr { get; private set; }

        public string ParsedCommand { get; private set; }

        public Dictionary<string, string> ParsedArgsForCommand 
        { 
            get { return argMap_.ContainsKey(ParsedCommand) ? argMap_[ParsedCommand] : null; } 
        }

        public static bool TryParse(string[] args, out Arguments parsedArgs)
        {
            Arguments tempArgs = null;
            bool succeeded = false;

            try
            {
                tempArgs = Parse(args);
                succeeded = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"failed to parse args: {ex.Message}");
            }

            parsedArgs = tempArgs;

            return succeeded;
        }

        private static Arguments Parse(string[] args)
        {
            if (args == null) throw new ArgumentNullException(nameof(args));
            if (args.Length == 0) throw new ArgumentException(nameof(args));

            Arguments parsedArgs = new Arguments(args);

            var command = args[0];
            if (!helpMap_.ContainsKey(command)) throw new ArgumentException($"'{command}' is not a valid command; see 'help'.");

            parsedArgs.ParsedCommand = command;
            var requiresParams = commandParams_[command].Count > 0;
            if (requiresParams && args.Length <= 1)
                throw new ArgumentException($"insufficient parameters passed for command '{command}'; see 'help {command}' for details");

            if (args.Length > 1)
            {
                var unparsedArgsForCmd = new string[args.Length - 1];
                Array.Copy(args, 1, unparsedArgsForCmd, 0, unparsedArgsForCmd.Length);

                parsedArgs.argMap_[command] = ParseArgsForCommand(command, args, 1);
            }

            return parsedArgs;
        }

        private static Dictionary<string, string> ParseArgsForCommand(string command, string[] args, int startIdx)
        {
            // caller validated params
            var result = new Dictionary<string, string>(StringComparer.InvariantCultureIgnoreCase);

            // syntax is <cmd> <para1>=<valPara1> <para2>=<valPara2> ...
            // retrieve the supported params
            var supportedParams = commandParams_[command];
            var expectedParamCount = command.Equals(nameof(Actions.Help), StringComparison.InvariantCultureIgnoreCase) ? 1 : 2;
            for (int idx = startIdx; idx < args.Length; idx++)
            {
                var splitParams = args[idx].Split('=', StringSplitOptions.RemoveEmptyEntries);
                var paramName = splitParams[0].Trim();
                if (splitParams.Length < expectedParamCount
                    || !supportedParams.Contains(paramName))
                    throw new ArgumentException($"parameter '{paramName}' is not supported for command '{command}', or is improperly formed; see 'help {command}'.");

                if (splitParams.Length > 1) // 'help' has single-value parameters
                {
                    var tempResult = splitParams[1].Trim();    // recombine values which may contain the splitter
                    for (int valIdx = 2; valIdx < splitParams.Length; valIdx++)
                    {
                        tempResult += $"={splitParams[valIdx]}";
                    }
                    result[paramName] = tempResult;
                }
                else
                    result[paramName] = String.Empty;
            }

            return result;
        }

        public static string GetCommandHelp(string command)
        {
            if (!String.IsNullOrWhiteSpace(command)
                && helpMap_.TryGetValue(command, out string commandHelp))
                return commandHelp;

            return helpMap_[nameof(Actions.Help)];
        }
    }
}
