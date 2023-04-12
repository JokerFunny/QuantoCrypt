using QuantoCrypt.Common.Parameters;

namespace QuantoCrypt.Common.BlockCipher
{
    /// <summary>
    /// Implementation of the Electronic codebook (ECB) encryption mode. 
    /// The message is divided into blocks, and each block is encrypted separately.
    /// </summary>
    public class EcbBlockCipher : IBlockCipherMode
    {
        internal static IBlockCipherMode GetBlockCipherMode(IBlockCipher blockCipher)
        {
            if (blockCipher is IBlockCipherMode blockCipherMode)
                return blockCipherMode;

            return new EcbBlockCipher(blockCipher);
        }

        private readonly IBlockCipher _rCipher;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="cipher">Target <see cref="IBlockCipher"/>.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="cipher"/> is null.</exception>
        public EcbBlockCipher(IBlockCipher cipher)
        {
            _rCipher = cipher ?? throw new ArgumentNullException(nameof(cipher));
        }

        public bool IsPartialBlockOkay => false;

        public string AlgorithmName => _rCipher.AlgorithmName + "/ECB";

        public int GetBlockSize()
            => _rCipher.GetBlockSize();

        public IBlockCipher UnderlyingCipher => _rCipher;

        public void Init(bool forEncryption, ICipherParameter parameters)
            => _rCipher.Init(forEncryption, parameters);

        public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
            => _rCipher.ProcessBlock(inBuf, inOff, outBuf, outOff);

        public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
            => _rCipher.ProcessBlock(input, output);

        public void Reset()
        { }
    }
}
