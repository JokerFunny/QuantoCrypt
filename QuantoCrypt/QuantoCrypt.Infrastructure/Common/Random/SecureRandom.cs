using QuantoCrypt.Infrastructure.Common.Digest;
using QuantoCrypt.Infrastructure.Common.Random;
using QuantoCrypt.Infrastructure.Common.Utils;

namespace QuantoCrypt.Infrastructure.Common
{
    public class SecureRandom : System.Random
    {
        internal static readonly SecureRandom srArbitraryRandom = new SecureRandom(new VmpcRandomGenerator(), 16);

        private static long _sCounter = DateTime.UtcNow.Ticks;
        private static readonly double _srDoubleScale = 1.0 / Convert.ToDouble(1L << 53);
        private static readonly SecureRandom _srMasterRandom = new SecureRandom(new CryptoApiRandomGenerator());

        protected readonly IRandomGenerator prRandomGenerator;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <remarks>
        ///     Use SHA256.
        /// </remarks>
        public SecureRandom()
            : this(_CreatePrng("SHA256", true))
        { }

        /// <summary>
        /// Use the specified instance of IRandomGenerator as random source.
        /// </summary>
        /// <remarks>
        /// This constructor performs no seeding of either the <c>IRandomGenerator</c> or the
        /// constructed <c>SecureRandom</c>. It is the responsibility of the client to provide
        /// proper seed material as necessary/appropriate for the given <c>IRandomGenerator</c>
        /// implementation.
        /// </remarks>
        /// <param name="generator">The source to generate all random bytes from.</param>
        public SecureRandom(IRandomGenerator generator)
            : base(0)
        {
            prRandomGenerator = generator;
        }

        /// <summary>
        /// Use the specified instance of IRandomGenerator as random source with specific length of the seed.
        /// </summary>
        /// <remarks>
        /// This constructor performs no seeding of either the <c>IRandomGenerator</c> or the
        /// constructed <c>SecureRandom</c>. It is the responsibility of the client to provide
        /// proper seed material as necessary/appropriate for the given <c>IRandomGenerator</c>
        /// implementation.
        /// </remarks>
        /// <param name="generator">The source to generate all random bytes from.</param>
        /// <param name="autoSeedLengthInBytes">Length of the auto seed in bytes.</param>
        public SecureRandom(IRandomGenerator generator, int autoSeedLengthInBytes)
            : base(0)
        {
            _AutoSeed(generator, autoSeedLengthInBytes);

            prRandomGenerator = generator;
        }

        public override double NextDouble()
        {
            ulong x = (ulong)NextLong() >> 11;

            return Convert.ToDouble(x) * _srDoubleScale;
        }

        public virtual int NextInt()
        {
            Span<byte> bytes = stackalloc byte[4];

            NextBytes(bytes);
            return (int)Pack.BE_To_UInt32(bytes);
        }

        public virtual long NextLong()
        {
            Span<byte> bytes = stackalloc byte[8];

            NextBytes(bytes);
            return (long)Pack.BE_To_UInt64(bytes);
        }

        public static byte[] GetNextBytes(SecureRandom secureRandom, int length)
        {
            byte[] result = new byte[length];
            secureRandom.NextBytes(result);

            return result;
        }

        /// <summary>
        /// Create and auto-seed an instance based on the given algorithm.
        /// </summary>
        /// <remarks>Equivalent to GetInstance(algorithm, true).</remarks>
        /// <param name="algorithm">e.g. "SHA256PRNG".</param>
        public static SecureRandom GetInstance(string algorithm)
            => GetInstance(algorithm, true);

        /// <summary>
        /// Create an instance based on the given algorithm, with optional auto-seeding.
        /// </summary>
        /// <param name="algorithm">e.g. "SHA256PRNG".</param>
        /// <param name="autoSeed">If true, the instance will be auto-seeded.</param>
        public static SecureRandom GetInstance(string algorithm, bool autoSeed)
        {
            if (algorithm == null)
                throw new ArgumentNullException(nameof(algorithm));

            if (algorithm.EndsWith("PRNG", StringComparison.OrdinalIgnoreCase))
            {
                string digestName = algorithm.Substring(0, algorithm.Length - "PRNG".Length);

                DigestRandomGenerator prng = _CreatePrng(digestName, autoSeed);
                if (prng != null)
                    return new SecureRandom(prng);
            }

            throw new ArgumentException("Unrecognised PRNG algorithm: " + algorithm, "algorithm");
        }

        public virtual byte[] GenerateSeed(int length)
            => GetNextBytes(_srMasterRandom, length);

        public virtual void GenerateSeed(Span<byte> seed)
            => _srMasterRandom.NextBytes(seed);

        public virtual void SetSeed(byte[] seed)
            => prRandomGenerator.AddSeedMaterial(seed);

        public virtual void SetSeed(Span<byte> seed)
            => prRandomGenerator.AddSeedMaterial(seed);

        public virtual void SetSeed(long seed)
            => prRandomGenerator.AddSeedMaterial(seed);

        public override int Next()
            => NextInt() & int.MaxValue;

        public override int Next(int maxValue)
        {
            if (maxValue < 2)
            {
                if (maxValue < 0)
                    throw new ArgumentOutOfRangeException("maxValue", "cannot be negative");

                return 0;
            }

            int bits;

            // Test whether maxValue is a power of 2
            if ((maxValue & maxValue - 1) == 0)
            {
                bits = NextInt() & int.MaxValue;
                return (int)((long)bits * maxValue >> 31);
            }

            int result;
            do
            {
                bits = NextInt() & int.MaxValue;
                result = bits % maxValue;
            }
            while (bits - result + (maxValue - 1) < 0); // Ignore results near overflow

            return result;
        }

        public override int Next(int minValue, int maxValue)
        {
            if (maxValue <= minValue)
            {
                if (maxValue == minValue)
                    return minValue;

                throw new ArgumentException("maxValue cannot be less than minValue");
            }

            int diff = maxValue - minValue;
            if (diff > 0)
                return minValue + Next(diff);

            for (; ; )
            {
                int i = NextInt();

                if (i >= minValue && i < maxValue)
                    return i;
            }
        }

        public override void NextBytes(byte[] buf)
            => prRandomGenerator.NextBytes(buf);

        public virtual void NextBytes(byte[] buf, int off, int len)
            => prRandomGenerator.NextBytes(buf, off, len);

        public override void NextBytes(Span<byte> buffer)
        {
            if (prRandomGenerator != null)
            {
                prRandomGenerator.NextBytes(buffer);
            }
            else
            {
                byte[] tmp = new byte[buffer.Length];
                NextBytes(tmp);
                tmp.CopyTo(buffer);
            }
        }

        private static long _NextCounterValue()
            => Interlocked.Increment(ref _sCounter);

        private static DigestRandomGenerator _CreatePrng(string digestName, bool autoSeed)
        {
            IDigest digest = DigestUtilities.GetDigest(digestName);
            if (digest == null)
                return null;

            DigestRandomGenerator prng = new DigestRandomGenerator(digest);
            if (autoSeed)
                _AutoSeed(prng, 2 * digest.GetDigestSize());

            return prng;
        }

        private static void _AutoSeed(IRandomGenerator generator, int seedLength)
        {
            generator.AddSeedMaterial(_NextCounterValue());

            Span<byte> seed = seedLength <= 128
                ? stackalloc byte[seedLength]
                : new byte[seedLength];

            _srMasterRandom.NextBytes(seed);
            generator.AddSeedMaterial(seed);
        }
    }
}
