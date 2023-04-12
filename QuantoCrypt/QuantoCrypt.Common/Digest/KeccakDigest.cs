using QuantoCrypt.Common.Utilities;
using System.Buffers.Binary;
using System.Diagnostics;

namespace QuantoCrypt.Common.Digest
{
    /// <summary>
    /// Implementation of Keccak based on following KeccakNISTInterface.c from http://keccak.noekeon.org/.
    /// </summary>
    /// <remarks>
    ///     Following the naming conventions used in the C source code to enable easy review of the implementation.
    /// </remarks>
    public class KeccakDigest : IDigest
    {
        private static readonly ulong[] KeccakRoundConstants = new ulong[]{
            0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
            0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
            0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
            0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
            0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
            0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL
        };

        private readonly ulong[] _rState = new ulong[25];
        protected byte[] dataQueue = new byte[192];
        protected int rate;
        protected int bitsInQueue;
        protected internal int fixedOutputLength;
        protected bool squeezing;

        public KeccakDigest()
            : this(288)
        { }

        public KeccakDigest(int bitLength)
        {
            Init(bitLength);
        }

        public KeccakDigest(KeccakDigest source)
        {
            CopyIn(source);
        }

        private void CopyIn(KeccakDigest source)
        {
            Array.Copy(source._rState, 0, _rState, 0, source._rState.Length);
            Array.Copy(source.dataQueue, 0, dataQueue, 0, source.dataQueue.Length);
            rate = source.rate;
            bitsInQueue = source.bitsInQueue;
            fixedOutputLength = source.fixedOutputLength;
            squeezing = source.squeezing;
        }

        public virtual string AlgorithmName => "Keccak-" + fixedOutputLength;

        public virtual int GetDigestSize()
        {
            return fixedOutputLength >> 3;
        }

        public virtual void Update(byte input)
        {
            Absorb(input);
        }

        public virtual void BlockUpdate(byte[] input, int inOff, int len)
        {
            Absorb(input, inOff, len);
        }

        public virtual void BlockUpdate(ReadOnlySpan<byte> input)
        {
            Absorb(input);
        }

        public virtual int DoFinal(byte[] output, int outOff)
        {
            Squeeze(output, outOff, fixedOutputLength);

            Reset();

            return GetDigestSize();
        }

        public virtual int DoFinal(Span<byte> output)
        {
            int digestSize = GetDigestSize();
            Squeeze(output[..digestSize]);

            Reset();

            return digestSize;
        }

        protected virtual int DoFinal(byte[] output, int outOff, byte partialByte, int partialBits)
        {
            if (partialBits > 0)
            {
                AbsorbBits(partialByte, partialBits);
            }

            Squeeze(output, outOff, fixedOutputLength);

            Reset();

            return GetDigestSize();
        }

        public virtual void Reset()
        {
            Init(fixedOutputLength);
        }

        /// <summary>
        /// Return the size of block that the compression function is applied to in bytes.
        /// </summary>
        public virtual int GetByteLength()
        {
            return rate >> 3;
        }

        private void Init(int bitLength)
        {
            switch (bitLength)
            {
                case 128:
                case 224:
                case 256:
                case 288:
                case 384:
                case 512:
                    InitSponge(1600 - (bitLength << 1));
                    break;
                default:
                    throw new ArgumentException("must be one of 128, 224, 256, 288, 384, or 512.", "bitLength");
            }
        }

        private void InitSponge(int rate)
        {
            if (rate <= 0 || rate >= 1600 || (rate & 63) != 0)
                throw new InvalidOperationException("invalid rate value");

            this.rate = rate;
            Array.Clear(_rState, 0, _rState.Length);

            int i = dataQueue.Length;
            while (i > 0)
            {
                dataQueue[--i] = 0;
            }

            bitsInQueue = 0;
            squeezing = false;
            fixedOutputLength = (1600 - rate) >> 1;
        }

        protected void Absorb(byte data)
        {
            if ((bitsInQueue & 7) != 0)
                throw new InvalidOperationException("attempt to absorb with odd length queue");
            if (squeezing)
                throw new InvalidOperationException("attempt to absorb while squeezing");

            dataQueue[bitsInQueue >> 3] = data;
            if ((bitsInQueue += 8) == rate)
            {
                KeccakAbsorb(dataQueue);

                bitsInQueue = 0;
            }
        }

        protected void Absorb(byte[] data, int off, int len)
        {
            if ((bitsInQueue & 7) != 0)
                throw new InvalidOperationException("attempt to absorb with odd length queue");
            if (squeezing)
                throw new InvalidOperationException("attempt to absorb while squeezing");

            int bytesInQueue = bitsInQueue >> 3;
            int rateBytes = rate >> 3;

            int available = rateBytes - bytesInQueue;
            if (len < available)
            {
                Array.Copy(data, off, dataQueue, bytesInQueue, len);
                bitsInQueue += len << 3;

                return;
            }

            int count = 0;
            if (bytesInQueue > 0)
            {
                Array.Copy(data, off, dataQueue, bytesInQueue, available);
                count += available;

                KeccakAbsorb(dataQueue);
            }

            int remaining;
            while ((remaining = (len - count)) >= rateBytes)
            {
                KeccakAbsorb(data.AsSpan(off + count));

                count += rateBytes;
            }

            Array.Copy(data, off + count, dataQueue, 0, remaining);
            bitsInQueue = remaining << 3;
        }

        protected void Absorb(ReadOnlySpan<byte> data)
        {
            if ((bitsInQueue & 7) != 0)
                throw new InvalidOperationException("attempt to absorb with odd length queue");
            if (squeezing)
                throw new InvalidOperationException("attempt to absorb while squeezing");

            int bytesInQueue = bitsInQueue >> 3;
            int rateBytes = rate >> 3;

            int len = data.Length;
            int available = rateBytes - bytesInQueue;
            if (len < available)
            {
                data.CopyTo(dataQueue.AsSpan(bytesInQueue));
                this.bitsInQueue += len << 3;
                return;
            }

            int count = 0;
            if (bytesInQueue > 0)
            {
                data[..available].CopyTo(dataQueue.AsSpan(bytesInQueue));
                count += available;
                KeccakAbsorb(dataQueue);
            }

            int remaining;
            while ((remaining = len - count) >= rateBytes)
            {
                KeccakAbsorb(data[count..]);
                count += rateBytes;
            }

            data[count..].CopyTo(dataQueue.AsSpan());
            this.bitsInQueue = remaining << 3;
        }

        protected void AbsorbBits(int data, int bits)
        {
            if (bits < 1 || bits > 7)
                throw new ArgumentException("must be in the range 1 to 7", "bits");
            if ((bitsInQueue & 7) != 0)
                throw new InvalidOperationException("attempt to absorb with odd length queue");
            if (squeezing)
                throw new InvalidOperationException("attempt to absorb while squeezing");

            int mask = (1 << bits) - 1;
            dataQueue[bitsInQueue >> 3] = (byte)(data & mask);

            // NOTE: After this, bitsInQueue is no longer a multiple of 8, so no more absorbs will work
            bitsInQueue += bits;
        }

        private void PadAndSwitchToSqueezingPhase()
        {
            Debug.Assert(bitsInQueue < rate);

            dataQueue[bitsInQueue >> 3] |= (byte)(1 << (bitsInQueue & 7));

            if (++bitsInQueue == rate)
            {
                KeccakAbsorb(dataQueue);
            }
            else
            {
                int full = bitsInQueue >> 6, partial = bitsInQueue & 63;
                int off = 0;
                for (int i = 0; i < full; ++i)
                {
                    _rState[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(dataQueue.AsSpan(off));
                    off += 8;
                }
                if (partial > 0)
                {
                    ulong mask = (1UL << partial) - 1UL;
                    _rState[full] ^= BinaryPrimitives.ReadUInt64LittleEndian(dataQueue.AsSpan(off)) & mask;
                }
            }

            _rState[(rate - 1) >> 6] ^= (1UL << 63);

            bitsInQueue = 0;
            squeezing = true;
        }

        protected void Squeeze(byte[] output, int offset, long outputLength)
        {
            if (!squeezing)
            {
                PadAndSwitchToSqueezingPhase();
            }
            if ((outputLength & 7L) != 0L)
                throw new InvalidOperationException("outputLength not a multiple of 8");

            long i = 0;
            while (i < outputLength)
            {
                if (bitsInQueue == 0)
                {
                    KeccakExtract();
                }
                int partialBlock = (int)System.Math.Min((long)bitsInQueue, outputLength - i);
                Array.Copy(dataQueue, (rate - bitsInQueue) >> 3, output, offset + (int)(i >> 3), partialBlock >> 3);
                bitsInQueue -= partialBlock;
                i += partialBlock;
            }
        }

        protected void Squeeze(Span<byte> output)
        {
            if (!squeezing)
            {
                PadAndSwitchToSqueezingPhase();
            }
            long outputLength = (long)output.Length << 3;

            long i = 0;
            while (i < outputLength)
            {
                if (bitsInQueue == 0)
                {
                    KeccakExtract();
                }
                int partialBlock = (int)System.Math.Min(bitsInQueue, outputLength - i);
                dataQueue.AsSpan((rate - bitsInQueue) >> 3, partialBlock >> 3).CopyTo(output[(int)(i >> 3)..]);
                bitsInQueue -= partialBlock;
                i += partialBlock;
            }
        }

        private void KeccakAbsorb(ReadOnlySpan<byte> data)
        {
            int count = rate >> 6, off = 0;
            for (int i = 0; i < count; ++i)
            {
                _rState[i] ^= BinaryPrimitives.ReadUInt64LittleEndian(data[off..]);
                off += 8;
            }

            KeccakPermutation(_rState);
        }

        private void KeccakExtract()
        {
            KeccakPermutation(_rState);

            PackUtilities.UInt64_To_LE(_rState, 0, rate >> 6, dataQueue, 0);

            bitsInQueue = rate;
        }

        internal static void KeccakPermutation(Span<ulong> A)
        {
            var bounds = A[24];

            ulong a00 = A[0], a01 = A[1], a02 = A[2], a03 = A[3], a04 = A[4];
            ulong a05 = A[5], a06 = A[6], a07 = A[7], a08 = A[8], a09 = A[9];
            ulong a10 = A[10], a11 = A[11], a12 = A[12], a13 = A[13], a14 = A[14];
            ulong a15 = A[15], a16 = A[16], a17 = A[17], a18 = A[18], a19 = A[19];
            ulong a20 = A[20], a21 = A[21], a22 = A[22], a23 = A[23], a24 = A[24];

            for (int i = 0; i < 24; i++)
            {
                // theta
                ulong c0 = a00 ^ a05 ^ a10 ^ a15 ^ a20;
                ulong c1 = a01 ^ a06 ^ a11 ^ a16 ^ a21;
                ulong c2 = a02 ^ a07 ^ a12 ^ a17 ^ a22;
                ulong c3 = a03 ^ a08 ^ a13 ^ a18 ^ a23;
                ulong c4 = a04 ^ a09 ^ a14 ^ a19 ^ a24;

                ulong d1 = LongUtilities.RotateLeft(c1, 1) ^ c4;
                ulong d2 = LongUtilities.RotateLeft(c2, 1) ^ c0;
                ulong d3 = LongUtilities.RotateLeft(c3, 1) ^ c1;
                ulong d4 = LongUtilities.RotateLeft(c4, 1) ^ c2;
                ulong d0 = LongUtilities.RotateLeft(c0, 1) ^ c3;

                a00 ^= d1; a05 ^= d1; a10 ^= d1; a15 ^= d1; a20 ^= d1;
                a01 ^= d2; a06 ^= d2; a11 ^= d2; a16 ^= d2; a21 ^= d2;
                a02 ^= d3; a07 ^= d3; a12 ^= d3; a17 ^= d3; a22 ^= d3;
                a03 ^= d4; a08 ^= d4; a13 ^= d4; a18 ^= d4; a23 ^= d4;
                a04 ^= d0; a09 ^= d0; a14 ^= d0; a19 ^= d0; a24 ^= d0;

                // rho/pi
                c1 = LongUtilities.RotateLeft(a01, 1);
                a01 = LongUtilities.RotateLeft(a06, 44);
                a06 = LongUtilities.RotateLeft(a09, 20);
                a09 = LongUtilities.RotateLeft(a22, 61);
                a22 = LongUtilities.RotateLeft(a14, 39);
                a14 = LongUtilities.RotateLeft(a20, 18);
                a20 = LongUtilities.RotateLeft(a02, 62);
                a02 = LongUtilities.RotateLeft(a12, 43);
                a12 = LongUtilities.RotateLeft(a13, 25);
                a13 = LongUtilities.RotateLeft(a19, 8);
                a19 = LongUtilities.RotateLeft(a23, 56);
                a23 = LongUtilities.RotateLeft(a15, 41);
                a15 = LongUtilities.RotateLeft(a04, 27);
                a04 = LongUtilities.RotateLeft(a24, 14);
                a24 = LongUtilities.RotateLeft(a21, 2);
                a21 = LongUtilities.RotateLeft(a08, 55);
                a08 = LongUtilities.RotateLeft(a16, 45);
                a16 = LongUtilities.RotateLeft(a05, 36);
                a05 = LongUtilities.RotateLeft(a03, 28);
                a03 = LongUtilities.RotateLeft(a18, 21);
                a18 = LongUtilities.RotateLeft(a17, 15);
                a17 = LongUtilities.RotateLeft(a11, 10);
                a11 = LongUtilities.RotateLeft(a07, 6);
                a07 = LongUtilities.RotateLeft(a10, 3);
                a10 = c1;

                // chi
                c0 = a00 ^ (~a01 & a02);
                c1 = a01 ^ (~a02 & a03);
                a02 ^= ~a03 & a04;
                a03 ^= ~a04 & a00;
                a04 ^= ~a00 & a01;
                a00 = c0;
                a01 = c1;

                c0 = a05 ^ (~a06 & a07);
                c1 = a06 ^ (~a07 & a08);
                a07 ^= ~a08 & a09;
                a08 ^= ~a09 & a05;
                a09 ^= ~a05 & a06;
                a05 = c0;
                a06 = c1;

                c0 = a10 ^ (~a11 & a12);
                c1 = a11 ^ (~a12 & a13);
                a12 ^= ~a13 & a14;
                a13 ^= ~a14 & a10;
                a14 ^= ~a10 & a11;
                a10 = c0;
                a11 = c1;

                c0 = a15 ^ (~a16 & a17);
                c1 = a16 ^ (~a17 & a18);
                a17 ^= ~a18 & a19;
                a18 ^= ~a19 & a15;
                a19 ^= ~a15 & a16;
                a15 = c0;
                a16 = c1;

                c0 = a20 ^ (~a21 & a22);
                c1 = a21 ^ (~a22 & a23);
                a22 ^= ~a23 & a24;
                a23 ^= ~a24 & a20;
                a24 ^= ~a20 & a21;
                a20 = c0;
                a21 = c1;

                // iota
                a00 ^= KeccakRoundConstants[i];
            }

            A[0] = a00; A[1] = a01; A[2] = a02; A[3] = a03; A[4] = a04;
            A[5] = a05; A[6] = a06; A[7] = a07; A[8] = a08; A[9] = a09;
            A[10] = a10; A[11] = a11; A[12] = a12; A[13] = a13; A[14] = a14;
            A[15] = a15; A[16] = a16; A[17] = a17; A[18] = a18; A[19] = a19;
            A[20] = a20; A[21] = a21; A[22] = a22; A[23] = a23; A[24] = a24;
        }
    }
}
