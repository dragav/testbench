using System;

namespace CertExplorer
{
    public enum LogLevel
    {
        Info,
        Verbose
    };

    public class Config
    {
        public Config() { }

        public LogLevel LogLevel { get; set; }

        public bool DoVerboseLogging
        {
            get { return LogLevel == LogLevel.Verbose; }
            set { LogLevel = LogLevel.Verbose; }
        }
    }

    public class CertExplorerConfig : Config 
    {
        public CertExplorerConfig() { }

        public string FindType { get; set; }
        public string FindValue { get; set; }
        public string StoreName { get; set; }
    }

    public class ProbeConfig : CertExplorerConfig 
    {
        public ProbeConfig() { }

        public ProbeConfig(string portsStr) 
        {
            if (!String.IsNullOrWhiteSpace(portsStr))
                Ports = ParsePortsStr(portsStr);
        }

        public int TimerInterval { get; set; }
        
        public string ServerUri { get; set; }

        public int[] Ports { get; protected set; }

        protected static int[] ParsePortsStr(string portsStr)
        {
            var splitPorts = portsStr.Split(',', StringSplitOptions.RemoveEmptyEntries);
            var result = new int[splitPorts.Length];
            for (int idx = 0; idx < result.Length; idx++)
            {
                result[idx] = int.Parse(splitPorts[idx]);
            }

            return result;
        }
    }

    public sealed class IssuerValidationConfig : ProbeConfig
    { 
        public IssuerValidationConfig() { }

        public IssuerValidationConfig(string portsStr)
            : base(portsStr)
        { }

        public string IssuerSource { get; set; }
        
        public string IssuerValue { get; set; }

        public string[] ParsedIssuers { get; private set; }

        //private string[] ParseIssuersFromSource(string source, string value)
        //{ }
    }

    public sealed class IssuerRetrievalConfig : Config
    {
        public IssuerRetrievalConfig() { }

        public string IssuerSource { get { return "URI"; } }

        public string IssuerValue { get; set; }

        public string[] ParsedIssuers { get; private set; }
    }
}
