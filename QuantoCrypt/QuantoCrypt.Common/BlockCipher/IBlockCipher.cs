using QuantoCrypt.Common.Parameters;

namespace QuantoCrypt.Common.BlockCipher
{
    /// <summary>
    /// Base interface for a symmetric key block cipher.
    /// </summary>
    public interface IBlockCipher
    {
        /// <summary>
        /// The name of the implements algorithm.
        /// </summary>
        string AlgorithmName { get; }

        /// <summary>
        /// Initialise the cipher.
        /// </summary>
        /// <param name="forEncryption">Initialise for encryption if true, for decryption if false.</param>
        /// <param name="parameters">The key or other data required by the cipher.</param>
        void Init(bool forEncryption, ICipherParameter parameters);

        /// <summary>
        /// Get the cipher block size.
        /// </summary>
        /// <returns>
        ///     The block size for this cipher, in bytes.
        /// </returns>
        int GetBlockSize();

        /// <summary>
        /// Process a block.
        /// </summary>
        /// <param name="inBuf">The input buffer.</param>
        /// <param name="inOff">The offset into <paramref>inBuf</paramref> that the input block begins.</param>
        /// <param name="outBuf">The output buffer.</param>
        /// <param name="outOff">The offset into <paramref>outBuf</paramref> to write the output block.</param>
        /// <returns>
        ///     The number of bytes processed and produced.
        /// </returns>
        int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff);

        /// <summary>
        /// Process a block.
        /// </summary>
        /// <param name="input">The input block as a span.</param>
        /// <param name="output">The output span.</param>
        /// <returns>
        ///     The number of bytes processed and produced.
        /// </returns>
        int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output);
    }
}
