using QuantoCrypt.Infrastructure.CipherSuite;

namespace QuantoCrypt.CipherSuites
{
    /// <summary>
    /// Implementation of the <see cref="ICipherSuiteProvider"/> for any cipher suites that needed.
    /// </summary>
    public sealed class CustomCipherSuiteProvider : ICipherSuiteProvider
    {
        public IReadOnlyList<ICipherSuite> SupportedCipherSuites { get; private set; }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="supportedCipherSuites">List of all supported cipher suites.</param>
        public CustomCipherSuiteProvider(List<ICipherSuite> supportedCipherSuites)
        {
            if (supportedCipherSuites == null || supportedCipherSuites.Count < 1)
                throw new ArgumentException($"Invalid {nameof(supportedCipherSuites)}! It shouldn't be empty and contains at least one cipher suite.");

            SupportedCipherSuites = supportedCipherSuites;
        }
    }
}
