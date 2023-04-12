using QuantoCrypt.Infrastructure.CipherSuite;

namespace QuantoCrypt.Internal.CipherSuite
{
    /// <summary>
    /// Implementation of the <see cref="ICipherSuiteProvider"/> for any cipher suites that needed.
    /// </summary>
    public sealed class CustomCipherSuiteProvider : ICipherSuiteProvider
    {
        public IReadOnlyDictionary<ICipherSuite, ulong> SupportedCipherSuites { get; private set; }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="supportedCipherSuites">List of all supported cipher suites.</param>
        /// <remarks>
        ///     Bit-mask will be generated for each algo in ascending order 
        ///     (supportedCipherSuites[0] == 1, supportedCipherSuites[1] == 2, supportedCipherSuites[2] == 4, etc.)
        /// </remarks>
        public CustomCipherSuiteProvider(List<ICipherSuite> supportedCipherSuites)
        {
            if (supportedCipherSuites == null || supportedCipherSuites.Count < 1)
                throw new ArgumentException($"Invalid {nameof(supportedCipherSuites)}! It shouldn't be empty and contains at least one cipher suite.");

            if (supportedCipherSuites.Count > 64)
                throw new ArgumentOutOfRangeException("Protocol supports only 64 or less cipher suites at once!");

            Dictionary<ICipherSuite, ulong> target = new() { { supportedCipherSuites[0], 1 } };

            for (int i = 1; i < supportedCipherSuites.Count; i++)
                target.Add(supportedCipherSuites[i], (ulong)System.Numerics.BigInteger.Pow(2, i));

            SupportedCipherSuites = target;
        }
    }
}
