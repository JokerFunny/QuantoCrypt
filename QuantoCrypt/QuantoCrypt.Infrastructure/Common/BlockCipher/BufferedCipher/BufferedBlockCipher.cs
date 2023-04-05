using QuantoCrypt.Infrastructure.Common.Parameters;

namespace QuantoCrypt.Infrastructure.Common.BlockCipher
{
    /// <summary>
    /// Handle work with <see cref="IBufferedCipher"/> with target <see cref="IBlockCipherMode"/>.
    /// </summary>
    public class BufferedBlockCipher : BufferedCipherBase
    {
        internal byte[] buf;
        internal int bufOff;
        internal bool _forEncryption;

        private readonly IBlockCipherMode _rCipherMode;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="cipher">Target <see cref="IBlockCipher"/>.</param>
        public BufferedBlockCipher(IBlockCipher cipher)
            : this(EcbBlockCipher.GetBlockCipherMode(cipher))
        { }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="cipherMode">Targe <see cref="IBlockCipherMode"/>.</param>
        public BufferedBlockCipher(IBlockCipherMode cipherMode)
        {
            if (cipherMode == null)
                throw new ArgumentNullException(nameof(cipherMode));

            _rCipherMode = cipherMode;
            buf = new byte[cipherMode.GetBlockSize()];
            bufOff = 0;
        }

        public override string AlgorithmName => _rCipherMode.AlgorithmName;

        /// <summary>
        /// Initialise the cipher.
        /// </summary>
        /// <remarks>
        ///     This doubles as the Init in the event that this cipher is being used as an IWrapper.
        /// </remarks>
        /// <param name="forEncryption">If true the cipher is initialised for encryption, otherwise - false.</param>
        /// <param name="parameters">Target <see cref="ICipherParameter"/>.</param>
        public override void Init(bool forEncryption, ICipherParameter parameters)
        {
            _forEncryption = forEncryption;

            Reset();

            _rCipherMode.Init(forEncryption, parameters);
        }

        /// <summary>
        /// Get the blocksize for the underlying cipher.
        /// </summary>
        /// <returns>
        ///     The blocksize for the underlying cipher.
        /// </returns>
        public override int GetBlockSize()
            => _rCipherMode.GetBlockSize();

        /// <summary>
        /// Get the size of the output buffer required for an update an input of <paramref name="length"/> bytes.
        /// </summary>
        /// <param name="length">The length of the input.</param>
        /// <returns>
        ///     The space required to accommodate a call to update with <paramref name="length"/> bytes of input.
        /// </returns>
        public override int GetUpdateOutputSize(int length)
        {
            int total = length + bufOff;
            int leftOver = total % buf.Length;

            return total - leftOver;
        }

        /// <summary>
        /// Get the size of the output buffer required for an update plus a DoFinal with an input of <paramref name="length"/> bytes.
        /// </summary>
        /// <param name="length">The length of the input.</param>
        /// <returns>
        ///     The space required to accommodate a call to update and doFinal with <paramref name="length"/> bytes of input.
        /// </returns>
        public override int GetOutputSize(int length)
            => length + bufOff;

        /// <summary>
        /// Process a single byte, producing an output block if necessary.
        /// </summary>
        /// <param name="input">The input byte.</param>
        /// <param name="output">The space for any output that might be produced.</param>
        /// <param name="outOff">The offset from which the output will be copied.</param>
        /// <returns>
        ///     The number of output bytes copied to out.
        /// </returns>
        public override int ProcessByte(byte input, byte[] output, int outOff)
        {
            buf[bufOff++] = input;

            if (bufOff == buf.Length)
            {
                if ((outOff + buf.Length) > output.Length)
                    throw new ArgumentException("Output buffer too short");

                bufOff = 0;
                return _rCipherMode.ProcessBlock(buf, 0, output, outOff);
            }

            return 0;
        }

        public override byte[] ProcessByte(byte input)
        {
            int outLength = GetUpdateOutputSize(1);

            byte[] outBytes = outLength > 0 ? new byte[outLength] : null;

            int pos = ProcessByte(input, outBytes, 0);

            if (outLength > 0 && pos < outLength)
            {
                byte[] tmp = new byte[pos];
                Array.Copy(outBytes, 0, tmp, 0, pos);
                outBytes = tmp;
            }

            return outBytes;
        }

        public override int ProcessByte(byte input, Span<byte> output)
        {
            buf[bufOff++] = input;

            if (bufOff == buf.Length)
            {
                if (output.Length < buf.Length)
                    throw new ArgumentException("Output buffer too short");

                bufOff = 0;
                return _rCipherMode.ProcessBlock(buf, output);
            }

            return 0;
        }

        /// <summary>
        /// Process an array of bytes, producing output if necessary.
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">The offset at which the input data starts.</param>
        /// <param name="length">The number of bytes to be copied out of the input array.</param>
        /// <returns>
        ///     The output that might be produced.
        /// </returns>
        public override byte[] ProcessBytes(byte[] input, int inOff, int length)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));
            if (length < 1)
                return null;

            int outLength = GetUpdateOutputSize(length);

            byte[] outBytes = outLength > 0 ? new byte[outLength] : null;

            int pos = ProcessBytes(input, inOff, length, outBytes, 0);

            if (outLength > 0 && pos < outLength)
            {
                byte[] tmp = new byte[pos];
                Array.Copy(outBytes, 0, tmp, 0, pos);
                outBytes = tmp;
            }

            return outBytes;
        }

        /// <summary>
        /// Process an array of bytes, producing output if necessary.
        /// </summary>
        /// <param name="input">The input byte array.</param>
        /// <param name="inOff">The offset at which the input data starts.</param>
        /// <param name="length">The number of bytes to be copied out of the input array.</param>
        /// <param name="output">The space for any output that might be produced.</param>
        /// <param name="outOff">The offset from which the output will be copied.</param>
        /// <returns>
        ///     The number of output bytes copied to <paramref name="output"/>.
        /// </returns>
        public override int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            if (length < 1)
            {
                if (length < 0)
                    throw new ArgumentException("Can't have a negative input length!");
                return 0;
            }

            Span<byte> bytesToProcees = output == null 
                ? Span<byte>.Empty 
                : output.AsSpan(outOff);

            return ProcessBytes(input.AsSpan(inOff, length), bytesToProcees);
        }

        /// <summary>
        /// Process an <see cref="Span{T}"/> of bytes, producing output if necessary.
        /// </summary>
        /// <param name="input">The input byte <see cref="Span{T}"/>.</param>
        /// <param name="output">The output <see cref="Span{T}"/>.</param>
        /// <returns>
        ///     The number of output bytes copied to <paramref name="output"/>.
        /// </returns>
        public override int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int resultLen = 0;
            int blockSize = buf.Length;
            int available = blockSize - bufOff;
            if (input.Length >= available)
            {
                input[..available].CopyTo(buf.AsSpan(bufOff));
                input = input[available..];

                int total = blockSize + input.Length;
                if (output.Length < total)
                {
                    if (output.Length < total - total % blockSize)
                        throw new ArgumentException("Output buffer too short");
                }

                resultLen = _rCipherMode.ProcessBlock(buf, output);
                bufOff = 0;

                while (input.Length >= blockSize)
                {
                    resultLen += _rCipherMode.ProcessBlock(input, output[resultLen..]);
                    input = input[blockSize..];
                }
            }
            input.CopyTo(buf.AsSpan(bufOff));
            bufOff += input.Length;
            return resultLen;
        }

        public override byte[] DoFinal()
        {
            byte[] outBytes = sEmptyBuffer;

            int length = GetOutputSize(0);
            if (length > 0)
            {
                outBytes = new byte[length];

                int pos = DoFinal(outBytes, 0);
                if (pos < outBytes.Length)
                {
                    byte[] tmp = new byte[pos];
                    Array.Copy(outBytes, 0, tmp, 0, pos);
                    outBytes = tmp;
                }
            }
            else
                Reset();

            return outBytes;
        }

        public override byte[] DoFinal(byte[] input, int inOff, int inLen)
        {
            if (input == null)
                throw new ArgumentNullException(nameof(input));

            int length = GetOutputSize(inLen);

            byte[] outBytes = sEmptyBuffer;

            if (length > 0)
            {
                outBytes = new byte[length];

                int pos = (inLen > 0)
                    ? ProcessBytes(input, inOff, inLen, outBytes, 0)
                    : 0;

                pos += DoFinal(outBytes, pos);

                if (pos < outBytes.Length)
                {
                    byte[] tmp = new byte[pos];
                    Array.Copy(outBytes, 0, tmp, 0, pos);
                    outBytes = tmp;
                }
            }
            else
                Reset();

            return outBytes;
        }

        /// <summary>
        /// Process the last block in the buffer.
        /// </summary>
        /// <param name="output">The array the block currently being held is copied into.</param>
        /// <param name="outOff">The offset at which the copying starts.</param>
        /// <returns>
        ///     The number of output bytes copied to <paramref name="output"/>.
        /// </returns>
        public override int DoFinal(byte[] output, int outOff)
        {
            try
            {
                if (bufOff != 0)
                {
                    if (!_rCipherMode.IsPartialBlockOkay)
                        throw new ArgumentException("Data not block size aligned");
                    if (outOff > (output.Length - bufOff))
                        throw new ArgumentException("Output buffer too short for DoFinal()");

                    // Can't copy directly, or we may write too much output
                    _rCipherMode.ProcessBlock(buf, 0, buf, 0);
                    Array.Copy(buf, 0, output, outOff, bufOff);
                }

                return bufOff;
            }
            finally
            {
                Reset();
            }
        }

        /// <summary>
        /// Process the last block in the buffer.
        /// </summary>
        /// <param name="output">The <see cref="Span{T}"/> the block currently being held is copied into.</param>
        /// <returns>
        ///     The number of output bytes copied to <paramref name="output"/>.
        /// </returns>
        public override int DoFinal(Span<byte> output)
        {
            try
            {
                if (bufOff != 0)
                {
                    if (!_rCipherMode.IsPartialBlockOkay)
                        throw new ArgumentException("Data not block size aligned");
                    if (output.Length < bufOff)
                        throw new ArgumentException("Output buffer too short for DoFinal()");

                    // Can't copy directly, or we may write too much output
                    _rCipherMode.ProcessBlock(buf, buf);
                    buf.AsSpan(0, bufOff).CopyTo(output);
                }

                return bufOff;
            }
            finally
            {
                Reset();
            }
        }

        /// <summary>
        /// Reset the buffer and cipher. After resetting the object is in the same state as it was after the last init (if there was one).
        /// </summary>
        public override void Reset()
        {
            Array.Clear(buf, 0, buf.Length);
            bufOff = 0;

            _rCipherMode.Reset();
        }
    }
}
