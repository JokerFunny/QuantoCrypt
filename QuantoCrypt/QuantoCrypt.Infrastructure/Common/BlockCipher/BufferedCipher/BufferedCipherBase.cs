using QuantoCrypt.Infrastructure.Common.Parameters;

namespace QuantoCrypt.Infrastructure.Common.BlockCipher
{
    /// <summary>
    /// Base for any implementation of <see cref="IBufferedCipher"/>.
    /// </summary>
    public abstract class BufferedCipherBase : IBufferedCipher
    {
        protected static readonly byte[] sEmptyBuffer = new byte[0];

        public abstract string AlgorithmName { get; }

        public abstract void Init(bool forEncryption, ICipherParameter parameters);

        public abstract int GetBlockSize();

        public abstract int GetOutputSize(int inputLen);
        public abstract int GetUpdateOutputSize(int inputLen);

        public abstract byte[] ProcessByte(byte input);

        public virtual int ProcessByte(byte input, byte[] output, int outOff)
        {
            byte[] outBytes = ProcessByte(input);
            if (outBytes == null)
                return 0;

            if (outOff + outBytes.Length > output.Length)
                throw new ArgumentException("Output buffer too short");

            outBytes.CopyTo(output, outOff);

            return outBytes.Length;
        }

        public abstract int ProcessByte(byte input, Span<byte> output);

        public virtual byte[] ProcessBytes(byte[] input)
            => ProcessBytes(input, 0, input.Length);

        public abstract byte[] ProcessBytes(byte[] input, int inOff, int length);

        public virtual int ProcessBytes(byte[] input, byte[] output, int outOff)
            => ProcessBytes(input, 0, input.Length, output, outOff);

        public virtual int ProcessBytes(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            byte[] outBytes = ProcessBytes(input, inOff, length);
            if (outBytes == null)
                return 0;

            if (outOff + outBytes.Length > output.Length)
                throw new ArgumentException("Output buffer too short");

            outBytes.CopyTo(output, outOff);

            return outBytes.Length;
        }

        public abstract int ProcessBytes(ReadOnlySpan<byte> input, Span<byte> output);

        public abstract byte[] DoFinal();

        public virtual byte[] DoFinal(byte[] input)
            => DoFinal(input, 0, input.Length);

        public abstract byte[] DoFinal(byte[] input, int inOff, int length);

        public virtual int DoFinal(byte[] output, int outOff)
        {
            byte[] outBytes = DoFinal();
            if (outOff + outBytes.Length > output.Length)
                throw new ArgumentException("Output buffer too short");

            outBytes.CopyTo(output, outOff);

            return outBytes.Length;
        }

        public virtual int DoFinal(byte[] input, byte[] output, int outOff)
            => DoFinal(input, 0, input.Length, output, outOff);

        public virtual int DoFinal(byte[] input, int inOff, int length, byte[] output, int outOff)
        {
            int len = ProcessBytes(input, inOff, length, output, outOff);
            len += DoFinal(output, outOff + len);

            return len;
        }

        public abstract int DoFinal(Span<byte> output);

        public virtual int DoFinal(ReadOnlySpan<byte> input, Span<byte> output)
        {
            int len = ProcessBytes(input, output);
            len += DoFinal(output[len..]);

            return len;
        }

        public abstract void Reset();
    }
}
