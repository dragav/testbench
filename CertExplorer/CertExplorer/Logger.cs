namespace CertExplorer
{
    using System;
    using System.IO;
    
    public sealed class Logger : IDisposable
    {
        private readonly string filePath_;
        private readonly bool logToFile_;
        private bool disposed = false;
        private StreamWriter fs_;

        public Logger() 
        {
            logToFile_ = false;
            LogVerboseToConsole = false;
        }

        public Logger(string filePath) 
        {
            if (String.IsNullOrWhiteSpace(filePath)) throw new ArgumentException(nameof(filePath));

            filePath_ = filePath;
            if (File.Exists(filePath_))
            {
                Console.WriteLine($"Deleting and re-creating existing log file {filePath_}");
                File.Delete(filePath_);
            }

            fs_ = File.CreateText(filePath_);
            logToFile_ = true;
            Console.WriteLine($"{DateTime.UtcNow.ToString("u")} log file created at {filePath_}");

            LogVerboseToConsole = false;
        }

        ~Logger()
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
                    if (fs_ != null)
                    {
                        fs_.Flush();
                        fs_.Close();
                    }
                }

                disposed = true;
            }
        }

        public bool LogVerboseToConsole { get; set; }

        public void Log(LogLevel level, string line)
        {
            if (String.IsNullOrWhiteSpace(line)) throw new ArgumentException(nameof(line));

            if (logToFile_)
            {
                try
                {
                    fs_.WriteLine(line);
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"logging to {filePath_} failed: {ex.Message}");
                }
            }

            if (level != LogLevel.Verbose
                || LogVerboseToConsole)
            {
                Console.WriteLine(line);
            }
        }
    }
}
