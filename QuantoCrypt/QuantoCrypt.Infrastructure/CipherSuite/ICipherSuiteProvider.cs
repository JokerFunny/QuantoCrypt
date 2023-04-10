namespace QuantoCrypt.Infrastructure.CipherSuite
{
    /// <summary>
    /// Provides all supported <see cref="ICipherSuite"/>.
    /// </summary>
    public interface ICipherSuiteProvider
    {
        /// <summary>
        /// All supported <see cref="ICipherSuite"/> with bit-mask value.
        /// </summary>
        public IReadOnlyDictionary<ICipherSuite, ulong> SupportedCipherSuites { get; }
    }
}
