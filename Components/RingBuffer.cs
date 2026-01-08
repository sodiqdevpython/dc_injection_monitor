using System;

namespace dc_injection_monitor.Components
{
    public sealed class RingBuffer<T>
    {
        private readonly T[] _buf;
        private int _head;
        private int _count;
        private readonly object _lock = new object();

        public int Capacity { get { return _buf.Length; } }
        public int Count { get { lock (_lock) return _count; } }

        public RingBuffer(int capacity)
        {
            if (capacity <= 0) throw new ArgumentOutOfRangeException(nameof(capacity));
            _buf = new T[capacity];
        }

        public void Add(T item)
        {
            lock (_lock)
            {
                if (_count < _buf.Length)
                {
                    int tail = (_head + _count) % _buf.Length;
                    _buf[tail] = item;
                    _count++;
                }
                else
                {
                    _buf[_head] = item;
                    _head = (_head + 1) % _buf.Length;
                }
            }
        }
        public void ScanNewest(Func<T, bool> predicate, Action<T> onHit, Func<bool> shouldStop = null)
        {
            if (predicate == null) throw new ArgumentNullException(nameof(predicate));
            if (onHit == null) throw new ArgumentNullException(nameof(onHit));

            lock (_lock)
            {
                int cap = _buf.Length;

                for (int i = 0; i < _count; i++)
                {
                    if (shouldStop != null && shouldStop())
                        return;

                    int idx = (_head + _count - 1 - i) % cap;
                    if (idx < 0) idx += cap;

                    T item = _buf[idx];
                    if (predicate(item))
                        onHit(item);
                }
            }
        }
    }
}
