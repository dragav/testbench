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

    public sealed class ProbeConfig : CertExplorerConfig 
    {
        public ProbeConfig() { }

        public ProbeConfig(string portsStr) 
        {
            if (!String.IsNullOrWhiteSpace(portsStr))
                Ports = ParsePortsStr(portsStr);
        }

        public int TimerInterval { get; set; }
        
        public string ServerUri { get; set; }

        public int[] Ports { get; private set; }

        private static int[] ParsePortsStr(string portsStr)
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
}
