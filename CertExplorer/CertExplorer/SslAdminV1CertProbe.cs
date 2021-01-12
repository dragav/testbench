namespace CertExplorer
{
    using System;
    using System.Security.Cryptography.X509Certificates;
    using System.Threading;

    public sealed class CertificateProbe : IDisposable
    {
        private static readonly string v1IssuerPrefix = "Microsoft IT TLS CA";
        private readonly string localStore_;
        private readonly X509FindType localFindType_;
        private readonly string localFindValue_;
        private readonly ServerCertExplorer serverCertExplorer_;
        private readonly TimedProbe probeDriver_;
        private readonly Logger logger_;
        private bool disposed = false;
        private readonly bool doFind_;
        private readonly bool doProbe_;

        public CertificateProbe(ProbeConfig config, string logFilePath)
        {
            doFind_ = !String.IsNullOrWhiteSpace(config.FindValue);
            doProbe_ = !String.IsNullOrWhiteSpace(config.ServerUri);

            if (doFind_)
            {
                localStore_ = config.StoreName;
                localFindType_ = Enum.Parse<X509FindType>(config.FindType);
                localFindValue_ = config.FindValue;
            }

            logger_ = new Logger(logFilePath);
            if (doProbe_)
            {
                serverCertExplorer_ = new ServerCertExplorer(config.ServerUri, config.Ports, logger_);
            }

            probeDriver_ = ConfigureProbeDriver(TimeSpan.FromSeconds(config.TimerInterval));

            CertExplorer.Logger = logger_;
            CertExplorer.Config = new CertExplorerConfig { 
                DoVerboseLogging = false, 
                FindType = config.FindType,
                FindValue = localFindValue_,
                StoreName = localStore_,
                LogLevel = config.LogLevel };
        }

        public CertificateProbe(
            string localCertStoreName,
            X509FindType localCertFindType,
            string localCertFindValue,
            string serverUri,
            int port,
            TimeSpan observationInterval,
            string logFilePath)
        {
            if (String.IsNullOrWhiteSpace(localCertStoreName)) throw new ArgumentException(nameof(localCertStoreName));
            if (String.IsNullOrWhiteSpace(localCertFindValue)) throw new ArgumentException(nameof(localCertFindValue));
            if (String.IsNullOrWhiteSpace(serverUri)) throw new ArgumentException(nameof(serverUri));

            localStore_ = localCertStoreName;
            localFindType_ = localCertFindType;
            localFindValue_ = localCertFindValue;
            logger_ = new Logger(logFilePath);
            serverCertExplorer_ = new ServerCertExplorer(serverUri, port, logger_);

            probeDriver_ = ConfigureProbeDriver(observationInterval);

            doFind_ = true;
            doProbe_ = true;

            CertExplorer.Logger = logger_;
            CertExplorer.Config = new CertExplorerConfig { DoVerboseLogging = false };
        }

        public CertificateProbe(
            string localCertStoreName,
            X509FindType localCertFindType,
            string localCertFindValue,
            string serverUri,
            int[] ports,
            TimeSpan observationInterval,
            string logFilePath)
        {
            if (String.IsNullOrWhiteSpace(localCertStoreName)) throw new ArgumentException(nameof(localCertStoreName));
            if (String.IsNullOrWhiteSpace(localCertFindValue)) throw new ArgumentException(nameof(localCertFindValue));
            if (String.IsNullOrWhiteSpace(serverUri)) throw new ArgumentException(nameof(serverUri));

            localStore_ = localCertStoreName;
            localFindType_ = localCertFindType;
            localFindValue_ = localCertFindValue;
            logger_ = new Logger(logFilePath);
            serverCertExplorer_ = new ServerCertExplorer(serverUri, ports, logger_);

            probeDriver_ = ConfigureProbeDriver(observationInterval);

            doFind_ = true;
            doProbe_ = true;

            CertExplorer.Logger = logger_;
            CertExplorer.Config = new CertExplorerConfig { DoVerboseLogging = false };
        }

        ~CertificateProbe()
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
                    probeDriver_.Dispose();
                    logger_.Dispose();
                }

                disposed = true;
            }
        }

        public TimedProbe ConfigureProbeDriver(TimeSpan observationInterval)
        {
            var probeDriver = new TimedProbe(observationInterval);
            if (doFind_)
                probeDriver.RegisterObserver("local cert observer", new TimerCallback(CertificateInventoryCallback), this);

            if (doProbe_)
                probeDriver.RegisterObserver("remote cert observer", new TimerCallback(ServerCertExplorer.Probe), serverCertExplorer_);

            return probeDriver;
        }

        public static void CertificateInventoryCallback(object state)
        {
            string correlationId = Guid.NewGuid().ToString("N").Substring(16);

            CertificateProbe typedState = (CertificateProbe)state;
            typedState.logger_.Log(LogLevel.Info, $"{DateTime.UtcNow:u} | {correlationId} | === beginning local certificate inventory; finding matches for {typedState.localFindType_}={typedState.localFindValue_} in {StoreLocation.LocalMachine}\\{typedState.localStore_}");

            var matchingCerts = CertExplorer.FindMatchingCertificates(
                StoreLocation.LocalMachine,
                typedState.localStore_,
                typedState.localFindType_,
                typedState.localFindValue_,
                secondaryFindValue: string.Empty,
                doTakeMostRecentOnly: false,
                excludeExpiredCerts: true);

            bool anyAtRisk = false;
            int countAtRisk = 0;

            foreach (var cert in matchingCerts)
            {
                var isLinked = CertExplorer.IsLinkedCertificate(cert, out string linkedToTP);
                var renewalTP = isLinked && !String.IsNullOrWhiteSpace(linkedToTP) ? linkedToTP : "(none)";
                var isAtRisk = cert.Issuer.Contains(v1IssuerPrefix);
                var certCN = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: false);
                var certIssuerCN = cert.GetNameInfo(X509NameType.SimpleName, forIssuer: true);
                var certDesc = String.Format($"TP={cert.Thumbprint}, CN={certCN}, issued by: {certIssuerCN}, NBF={cert.NotBefore.ToShortDateString()}, NA={cert.NotAfter.ToShortDateString()}, renewal={renewalTP}, at risk: {(isAtRisk ? "YES" : "no")}");
                typedState.logger_.Log(LogLevel.Info, $"{DateTime.UtcNow:u} | {correlationId} | cert probe | match: {certDesc}");
                anyAtRisk |= isAtRisk;
                if (isAtRisk) countAtRisk++;
            }

            typedState.logger_.Log(LogLevel.Info, $"{DateTime.UtcNow:u} | {correlationId} | === completed local certificate inventory; certs at risk: {countAtRisk}");
        }

        public void EndlessRun()
        {
            logger_.Log(LogLevel.Info, $"{DateTime.Now:u}: starting probe; press 'q'+enter to exit. Type any other key+enter to log a bookmark.");
            probeDriver_.Run();

            ConsoleKeyInfo keyInfo;

            do
            {
                while (!Console.KeyAvailable)
                    Thread.Sleep(250);

                keyInfo = Console.ReadKey();
                if (keyInfo.Key != ConsoleKey.Q)
                {
                    Console.WriteLine($"{DateTime.Now.ToShortTimeString()}: {keyInfo.KeyChar}");
                }
            } while (keyInfo.Key != ConsoleKey.Q);

            logger_.Log(LogLevel.Info, $"{DateTime.Now:u}: probe stopped.");
        }
    }
}
