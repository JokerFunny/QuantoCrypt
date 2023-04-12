using QuantoCrypt.Common.Parameters;

namespace QuantoCrypt.Common.BlockCipher
{
    /// <summary>
    /// Implements the Segmented Integer Counter (SIC) mode on top of a simple block _rCipher.
    /// </summary>
    public class SicBlockCipher : IBlockCipherMode
    {
        private readonly IBlockCipher _rCipher;
        private readonly int _rBlockSize;
        private readonly byte[] _rCounter;
        private readonly byte[] _rCounterOut;
        private byte[] _IV;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="cipher">Target <see cref="IBlockCipher"/>.</param>
        public SicBlockCipher(IBlockCipher cipher)
        {
            _rCipher = cipher;
            _rBlockSize = _rCipher.GetBlockSize();
            _rCounter = new byte[_rBlockSize];
            _rCounterOut = new byte[_rBlockSize];
            _IV = new byte[_rBlockSize];
        }

        /// <summary>
        /// The underlying block _rCipher that wrapped.
        /// </summary>
        public IBlockCipher UnderlyingCipher => _rCipher;

        public virtual void Init(bool forEncryption, ICipherParameter parameters)
        {
            if (parameters is not ParametersWithIV ivParam)
                throw new ArgumentException("CTR/SIC mode requires ParametersWithIV", "parameters");

            ivParam.IV.CopyTo(_IV);

            if (_rBlockSize < _IV.Length)
                throw new ArgumentException("CTR/SIC mode requires _IV no greater than: " + _rBlockSize + " bytes.");

            int maxCounterSize = Math.Min(8, _rBlockSize / 2);
            if (_rBlockSize - _IV.Length > maxCounterSize)
                throw new ArgumentException("CTR/SIC mode requires _IV of at least: " + (_rBlockSize - maxCounterSize) + " bytes.");

            Reset();

            // if null it's an _IV changed only.
            if (ivParam.Parameters != null)
                _rCipher.Init(true, ivParam.Parameters);
        }

        public virtual string AlgorithmName => _rCipher.AlgorithmName + "/SIC";

        public virtual bool IsPartialBlockOkay => true;

        public virtual int GetBlockSize()
            => _rCipher.GetBlockSize();

        public virtual int ProcessBlock(byte[] input, int inOff, byte[] output, int outOff)
        {
            _rCipher.ProcessBlock(_rCounter, 0, _rCounterOut, 0);

            // XOR the _rCounterOut with the plaintext producing the _rCipher text.
            for (int i = 0; i < _rCounterOut.Length; i++)
                output[outOff + i] = (byte)(_rCounterOut[i] ^ input[inOff + i]);

            // Increment the _rCounter
            int j = _rCounter.Length;
            while (--j >= 0 && ++_rCounter[j] == 0)
            { }

            return _rCounter.Length;
        }

        public virtual int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            _rCipher.ProcessBlock(_rCounter, 0, _rCounterOut, 0);

            // XOR the _rCounterOut with the plaintext producing the _rCipher text.
            for (int i = 0; i < _rCounterOut.Length; i++)
                output[i] = (byte)(_rCounterOut[i] ^ input[i]);

            // Increment the _rCounter
            int j = _rCounter.Length;
            while (--j >= 0 && ++_rCounter[j] == 0)
            { }

            return _rCounter.Length;
        }

        public virtual void Reset()
        {
            int i = _rCounter.Length;
            while (i > 0)
                _rCounter[--i] = 0;

            Array.Copy(_IV, 0, _rCounter, 0, _IV.Length);
        }
    }
}
