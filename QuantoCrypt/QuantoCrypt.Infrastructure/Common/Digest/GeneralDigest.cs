namespace QuantoCrypt.Infrastructure.Common.Digest
{
    /// <summary>
    /// Base implementation of MD4 family style digest as outlined in "Handbook of Applied Cryptography", pages 344 - 347.
    /// </summary>
    public abstract class GeneralDigest : IDigest
    {
        private const int BYTE_LENGTH = 64;

        private readonly byte[] _rXBuf;
        private int _xBufOff;

        private long _byteCount;

        internal GeneralDigest()
        {
            _rXBuf = new byte[4];
        }

        public void Update(byte input)
        {
            _rXBuf[_xBufOff++] = input;

            if (_xBufOff == _rXBuf.Length)
            {
                ProcessWord(_rXBuf, 0);
                _xBufOff = 0;
            }

            _byteCount++;
        }

        public void BlockUpdate(byte[] input, int inOff, int length)
        {
            length = Math.Max(0, length);

            // fill the current word
            int i = 0;
            if (_xBufOff != 0)
            {
                while (i < length)
                {
                    _rXBuf[_xBufOff++] = input[inOff + i++];
                    if (_xBufOff == 4)
                    {
                        ProcessWord(_rXBuf, 0);
                        _xBufOff = 0;
                        break;
                    }
                }
            }

            // process whole words.
            int limit = length - 3;
            for (; i < limit; i += 4)
                ProcessWord(input, inOff + i);

            // load in the remainder.
            while (i < length)
                _rXBuf[_xBufOff++] = input[inOff + i++];

            _byteCount += length;
        }

        public void BlockUpdate(ReadOnlySpan<byte> input)
        {
            int length = input.Length;

            // fill the current word
            int i = 0;
            if (_xBufOff != 0)
            {
                while (i < length)
                {
                    _rXBuf[_xBufOff++] = input[i++];
                    if (_xBufOff == 4)
                    {
                        ProcessWord(_rXBuf, 0);
                        _xBufOff = 0;
                        break;
                    }
                }
            }

            // process whole words.
            int limit = length - 3;
            for (; i < limit; i += 4)
                ProcessWord(input.Slice(i, 4));

            // load in the remainder.
            while (i < length)
                _rXBuf[_xBufOff++] = input[i++];

            _byteCount += length;
        }

        public void Finish()
        {
            long bitLength = (_byteCount << 3);

            //
            // add the pad bytes.
            //
            Update(128);

            while (_xBufOff != 0) 
                Update(0);

            ProcessLength(bitLength);
            ProcessBlock();
        }

        public virtual void Reset()
        {
            _byteCount = 0;
            _xBufOff = 0;

            Array.Clear(_rXBuf, 0, _rXBuf.Length);
        }

        public int GetByteLength()
            => BYTE_LENGTH;

        internal GeneralDigest(GeneralDigest t)
        {
            _rXBuf = new byte[t._rXBuf.Length];
            CopyIn(t);
        }

        protected void CopyIn(GeneralDigest t)
        {
            Array.Copy(t._rXBuf, 0, _rXBuf, 0, t._rXBuf.Length);

            _xBufOff = t._xBufOff;
            _byteCount = t._byteCount;
        }

        internal abstract void ProcessWord(byte[] input, int inOff);
        internal abstract void ProcessWord(ReadOnlySpan<byte> word);
        internal abstract void ProcessLength(long bitLength);
        internal abstract void ProcessBlock();
        public abstract string AlgorithmName { get; }
        public abstract int GetDigestSize();
        public abstract int DoFinal(byte[] output, int outOff);
        public abstract int DoFinal(Span<byte> output);
    }
}
