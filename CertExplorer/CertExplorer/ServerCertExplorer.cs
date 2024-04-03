namespace CertExplorer
{
    using Microsoft.Rest;
    using Newtonsoft.Json;
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;
    using static global::CertExplorer.CertExplorer;

    public sealed class ServerCertExplorer : IDisposable
    {
        private static readonly string v1IssuerPrefix = "Microsoft IT TLS CA";
        private bool disposed = false;
        private readonly string serverUri_;
        private readonly int[] ports_;
        Logger logger_;
        private HashSet<string> parsedIssuerSha1Tps_;
        private static readonly HttpClient httpClient_;

        static ServerCertExplorer()
        {
            var socketsHandler = new SocketsHttpHandler
            {
                PooledConnectionLifetime = TimeSpan.FromMinutes(2)
            };
            httpClient_ = new HttpClient(socketsHandler);
        }

        public ServerCertExplorer(string serverUri, int port, Logger logger)
        {
            if (String.IsNullOrWhiteSpace(serverUri)) throw new ArgumentException(nameof(serverUri));
            if (logger == null) throw new ArgumentNullException(nameof(logger));

            serverUri_ = serverUri;
            ports_ = new int[] { port };
            logger_ = logger;
        }

        public ServerCertExplorer(string serverUri, int[] ports, Logger logger)
        {
            if (String.IsNullOrWhiteSpace(serverUri)) throw new ArgumentException(nameof(serverUri));
            if (ports == null) throw new ArgumentNullException(nameof(ports));
            if (logger == null) throw new ArgumentNullException(nameof(logger));

            serverUri_ = serverUri;
            ports_ = ports;
            logger_ = logger;
        }

        ~ServerCertExplorer()
        {
            Dispose(false);
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!this.disposed)
            {
                if (disposing)
                {
                    if (httpClient_ != null)
                    {
                        httpClient_.CancelPendingRequests();
                    }
                }

                disposed = true;
            }
        }

        public static void Probe(object state)
        {
            string correlationId = Guid.NewGuid().ToString("N").Substring(16);
            ServerCertExplorer typedState = (ServerCertExplorer)state;
            var overallProbe = true;
            var overallAtRisk = false;
            typedState.logger_.Log(LogLevel.Info, $"{DateTime.UtcNow.ToString("u")} | {correlationId} | === beginning remote certificate probing");

            try
            {
                foreach (var port in typedState.ports_)
                {
                    using (var tcpClient = new TcpClient() { ReceiveTimeout = 5000, SendTimeout = 5 })
                    {
                        typedState.logger_.Log(LogLevel.Info, $"{DateTime.UtcNow.ToString("u")} | {correlationId} | endpoint probe | probing {typedState.serverUri_}:{port}..");
                        var portResult = typedState.TryProbeServerEndpoint(tcpClient, typedState.serverUri_, port, out X509Certificate2 serverCert);
                        overallProbe &= portResult;

                        if (!portResult)
                        {
                            typedState.logger_.Log(LogLevel.Info, $"{DateTime.UtcNow.ToString("u")} | {correlationId} | endpoint probe | failed to retrieve server cert for {typedState.serverUri_}:{port}");
                            continue;
                        }

                        if (serverCert == null)
                        {
                            typedState.logger_.Log(LogLevel.Info, $"{DateTime.UtcNow.ToString("u")} | {correlationId} | endpoint probe | server at {typedState.serverUri_}:{port} did not present a certificate");
                            continue;
                        }

                        var serverCertCN = serverCert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                        var serverCertIssuer = serverCert.GetNameInfo(X509NameType.SimpleName, forIssuer: true);
                        var portAtRisk = serverCertIssuer.Contains(v1IssuerPrefix);
                        overallAtRisk |= portAtRisk;
                        var serverCertDesc = String.Format($"TP={serverCert.Thumbprint}, CN={serverCertCN}, issued by: {serverCertIssuer}, NBF={serverCert.NotBefore.ToShortDateString()}, NA={serverCert.NotAfter.ToShortDateString()}, at risk: {(portAtRisk ? "YES" : "no")}");
                        typedState.logger_.Log(LogLevel.Info, $"{DateTime.UtcNow.ToString("u")} | {correlationId} | endpoint probe | server at {typedState.serverUri_}:{port} presented cert {serverCertDesc}");
                    }
                }
            }
            catch (Exception ex)
            {
                typedState.logger_.Log(LogLevel.Info, $"encountered {ex.GetType()}: {ex.Message}");
            }
            finally
            {
                var status = overallProbe ? (overallAtRisk? "YES" : "no") : ("undetermined");
                typedState.logger_.Log(LogLevel.Info, $"{DateTime.UtcNow.ToString("u")} | {correlationId} | === completed probing {typedState.serverUri_}; overall probing: {(overallProbe ? "succeeded" : "failed")}; overall at risk: {status}");
            }
        }

        public bool ValidateIssuer(IssuerValidationConfig config)
        {
            try 
            {
                if (!InitializeIssuerInfoIfNecessary(config))
                {
                    logger_.Log(LogLevel.Info, "failed to initialize issuer information");
                    return false;
                }

                X509Certificate2 serverCert;
                using (var tcpClient = new TcpClient() { ReceiveTimeout = 5000, SendTimeout = 5 })
                {
                    if (!TryProbeServerEndpoint(tcpClient, config.ServerUri, config.Ports[0], out serverCert))
                    {
                        logger_.Log(LogLevel.Info, "failed to probe server endpoint");
                        return false;
                    }
                }

                IsCertificateAMatchForFindValue certMatchingFn = CertExplorer.IsMatchBySubjectCommonName;
                if (String.IsNullOrWhiteSpace(config.FindValue))
                {
                    certMatchingFn = CertExplorer.AnyMatch;
                }
                if (!CertExplorer.TryValidateCertificate(serverCert, certMatchingFn, config.FindValue, parsedIssuerSha1Tps_, X509ChainStatusFlags.UntrustedRoot, out bool isValidCert, out X509ChainStatus[] statuses))
                {
                    logger_.Log(LogLevel.Info, "failed to complete certificate validation");
                    return false;
                }

                logger_.Log(LogLevel.Info, String.Format("certificate validation completed: {0}", isValidCert ? "success": "FAILED"));
                return isValidCert;
            }
            catch (Exception ex)
            {
                logger_.Log(LogLevel.Info, ex.Message);
            }

            return true;
        }

        delegate bool Parser(string source, out string[] output);

        private bool InitializeIssuerInfoIfNecessary(IssuerValidationConfig config)
        {
            if (null != parsedIssuerSha1Tps_)
            {
                logger_.Log(LogLevel.Info, "issuers already initialized, skipping;");
                return true;
            }

            string[] issuerSha1Tps = null;
            Parser parser = null;
            string sourceDesc = null;

            if (string.Equals(config.IssuerSource, "uri", StringComparison.InvariantCultureIgnoreCase))
            {
                parser = TryGetIssuerSha1TpsFromEndpoint;
                sourceDesc = "PKI endpoint";
            }
            else if (string.Equals(config.IssuerSource, "str", StringComparison.InvariantCultureIgnoreCase))
            {
                parser = TryGetIssuerSha1TpsFromString;
                sourceDesc = "input string";
            }
            else 
            {
                logger_.Log(LogLevel.Info, String.Format($"invalid issuer source '{config.IssuerSource}'"));
                return false;
            }

            if (!parser(config.IssuerValue, out issuerSha1Tps)
                || issuerSha1Tps.Length == 0)
            {
                logger_.Log(LogLevel.Info, String.Format($"failed to parse issuers from {sourceDesc}.."));
                return false;
            }
            parsedIssuerSha1Tps_ = new HashSet<string>(issuerSha1Tps, StringComparer.InvariantCultureIgnoreCase);
            logger_.Log(LogLevel.Info, String.Format($"successfully extracted {parsedIssuerSha1Tps_.Count} issuer TPs from {sourceDesc}.."));

            return true;
        }

        private static bool NoOpRemoteCertificateValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;
        }

        public bool TryProbeServerEndpoint(TcpClient tcpClient, string uri, int port, out X509Certificate2 serverCert)
        {
            serverCert = null;
            var result = false;

            SslStream sslStream = null;

            try
            {
                if (tcpClient.Connected)
                    return true;

                tcpClient.Connect(uri, port);
                sslStream = new SslStream(tcpClient.GetStream(),
                    leaveInnerStreamOpen: false,
                    userCertificateValidationCallback: new RemoteCertificateValidationCallback(NoOpRemoteCertificateValidationCallback),
                    userCertificateSelectionCallback: null);

                try
                {
                    sslStream.AuthenticateAsClient(uri);
                    serverCert = new X509Certificate2(sslStream.RemoteCertificate);
                    result = true;
                }
                catch (AuthenticationException ae)
                {
                    logger_.Log(LogLevel.Info, $"{DateTime.UtcNow.ToString("u")} | endpoint probe | failed to authenticate as client to {uri}:{port}: {ae}");
                }
            }
            catch (Exception ex)
            {
                logger_.Log(LogLevel.Info, $"{DateTime.UtcNow.ToString("u")} | endpoint probe | failed to probe {uri}:{port}: {ex.Message}");
            }
            finally 
            {
                if (sslStream != null) sslStream.Close();
                tcpClient.Close();
            }

            return result;
        }

        private bool TryGetIssuerSha1TpsFromEndpoint(string issuerUri, out string[] issuerSha1Tps)
        {
            issuerSha1Tps = null;
            if (new AutoIssuers("", logger_).TryGetIssuersFromEndpoint(issuerUri, out var issuerTree))
                issuerSha1Tps = AutoIssuers.GetIssuerTPs(issuerTree);

            return issuerSha1Tps != null;
        }

        private static bool TryGetIssuerSha1TpsFromString(string issuerVal, out string[] issuerSha1Tps)
        {
            issuerSha1Tps = null;

            try
            {
                string compactedIssuerVal = issuerVal.Replace(" ", String.Empty);
                char[] separators = new char[] { '\n', '\r', ',' };
                issuerSha1Tps = compactedIssuerVal.Split(separators, StringSplitOptions.RemoveEmptyEntries);

                return true;
            }
            catch (Exception ex) 
            { 
                Console.WriteLine(ex.ToString());
            }

            return false;
        }
    }
}
