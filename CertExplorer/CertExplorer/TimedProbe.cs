namespace CertExplorer
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Threading;

    public sealed class TimedProbe: IDisposable
    {
        private Dictionary<string, Timer> observers_;
        private TimeSpan interval_;
        private bool disposed = false;

        public TimedProbe(TimeSpan interval)
        {
            observers_ = new Dictionary<string, Timer>(10);
            interval_ = interval;
        }

        ~TimedProbe()
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
                    foreach(var entry in observers_)
                        entry.Value.Dispose();
                }

                disposed = true;
            }
        }

        public void RegisterObserver(string label, TimerCallback cb, Object state)
        {
            if (String.IsNullOrWhiteSpace(label)) throw new ArgumentException(nameof(label));
            if (cb == null) throw new ArgumentException(nameof(cb));
            if (state == null) throw new ArgumentException(nameof(state));

            // overwrite, this releases any previous timer; start suspended
            observers_[label] = new Timer(cb, state, Timeout.InfiniteTimeSpan, interval_);
        }

        public void Run()
        { 
            foreach (var entry in observers_)
            {
                entry.Value.Change(TimeSpan.Zero, interval_);
            }
        }

        public string DisplayObservers()
        {
            StringBuilder observers = new StringBuilder();
            observers.AppendFormat($"Registered observers on running on {interval_.TotalSeconds}s: ");
            foreach (var entry in observers_)
            {
                observers.AppendFormat($"{entry.Key}, ");
            }

            // trim end
            observers.Remove(observers.Length - 2, 2);

            return observers.ToString();
        }
    }
}
