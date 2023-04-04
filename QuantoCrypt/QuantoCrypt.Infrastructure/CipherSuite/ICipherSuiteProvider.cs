namespace QuantoCrypt.Infrastructure.CipherSuite
{
    /// <summary>
    /// Provides all supported <see cref="ICipherSuite"/>.
    /// </summary>
    public interface ICipherSuiteProvider
    {
        /// <summary>
        /// All supported <see cref="ICipherSuite"/>.
        /// </summary>
        public IReadOnlyList<ICipherSuite> SupportedCipherSuites { get; }
    }
}
