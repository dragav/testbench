namespace CertExplorer
{
    using System;
    using System.Net.Security;
    using System.Net.Sockets;
    using System.Security.Authentication;
    using System.Security.Cryptography.X509Certificates;

    public sealed class ServerCertExplorer
    {
        private static readonly string v1IssuerPrefix = "Microsoft IT TLS CA";

        private readonly string serverUri_;
        private readonly int[] ports_;
        Logger logger_;

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
    }
}
