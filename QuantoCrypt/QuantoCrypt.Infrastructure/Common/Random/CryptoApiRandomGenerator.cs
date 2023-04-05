using System.Security.Cryptography;

namespace QuantoCrypt.Infrastructure.Common.Random
{
    /// <summary>
    /// Uses <see cref="RandomNumberGenerator.Create"/> to get randomness generator.
    /// </summary>
    public sealed class CryptoApiRandomGenerator
        : IRandomGenerator, IDisposable
    {
        private readonly RandomNumberGenerator _rRandomNumberGenerator;

        /// <summary>
        /// Default ctor.
        /// </summary>
        public CryptoApiRandomGenerator()
            : this(RandomNumberGenerator.Create())
        { }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="randomNumberGenerator">Target <see cref="RandomNumberGenerator"/> to be used.</param>
        /// <exception cref="ArgumentNullException">If <paramref name="randomNumberGenerator"/> is null.</exception>
        public CryptoApiRandomGenerator(RandomNumberGenerator randomNumberGenerator)
        {
            _rRandomNumberGenerator = randomNumberGenerator ?? throw new ArgumentNullException(nameof(randomNumberGenerator));
        }

        // We don't care about the seed
        public void AddSeedMaterial(byte[] seed)
        { }

        // We don't care about the seed
        public void AddSeedMaterial(ReadOnlySpan<byte> inSeed)
        { }

        // We don't care about the seed
        public void AddSeedMaterial(long seed)
        { }

        public void NextBytes(byte[] bytes)
            => _rRandomNumberGenerator.GetBytes(bytes);

        public void NextBytes(byte[] bytes, int start, int len)
            => _rRandomNumberGenerator.GetBytes(bytes, start, len);

        public void NextBytes(Span<byte> bytes)
            => _rRandomNumberGenerator.GetBytes(bytes);

        public void Dispose()
        {
            _rRandomNumberGenerator.Dispose();

            GC.SuppressFinalize(this);
        }
    }
}
