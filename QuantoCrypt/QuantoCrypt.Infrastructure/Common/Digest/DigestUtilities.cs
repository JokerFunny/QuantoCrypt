namespace QuantoCrypt.Infrastructure.Common.Digest
{
    /// <remarks>
    /// Utility class for creating IDigests by names.
    /// </remarks>
    public static class DigestUtilities
    {
        private enum DigestAlgorithm
        {
            KECCAK_224, KECCAK_256, KECCAK_288, KECCAK_384, KECCAK_512,
            SHA_256, SHA_512,
            SHA_512_224, SHA_512_256,
            SHA3_224, SHA3_256, SHA3_384, SHA3_512,
            SHAKE128_256, SHAKE256_512,
        };

        private static readonly IDictionary<string, Func<IDigest>> _srDigestAlgorithmsByName =
            new Dictionary<string, Func<IDigest>>()
            {
                { "KECCAK-224", () => new KeccakDigest(224) },
                { "KECCAK-256", () => new KeccakDigest(256) },
                { "KECCAK-288", () => new KeccakDigest(288) },
                { "KECCAK-384", () => new KeccakDigest(384) },
                { "KECCAK-512", () => new KeccakDigest(512) },
                { "SHA-256", () => new Sha256Digest() },
                { "SHA-512", () => new Sha512Digest() },
                { "SHA3-224", () => new Sha3Digest(224) },
                { "SHA3-256", () => new Sha3Digest(256) },
                { "SHA3-384", () => new Sha3Digest(384) },
                { "SHA3-512", () => new Sha3Digest(512) },
                { "SHAKE128-256", () => new ShakeDigest(128) },
                { "SHAKE256-512", () => new ShakeDigest(256) },
            };

        /// <summary>
        /// Get target <see cref="IDigest"/> by <paramref name="algorithmName"/>.
        /// </summary>
        /// <param name="algorithmName">Name of the target <see cref="IDigest"/>.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static IDigest GetDigest(string algorithmName)
        {
            if (string.IsNullOrEmpty(algorithmName))
                throw new ArgumentNullException(nameof(algorithmName));

            if (_srDigestAlgorithmsByName.TryGetValue(algorithmName.ToUpperInvariant(), out Func<IDigest> iDigestCreator))
                return iDigestCreator.Invoke();

            throw new ArgumentException($"Digest [{algorithmName}] not recognised.");
        }
    }
}
