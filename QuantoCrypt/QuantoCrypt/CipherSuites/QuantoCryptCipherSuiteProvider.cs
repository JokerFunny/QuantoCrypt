using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Internal.CipherSuite;

namespace QuantoCrypt.CipherSuites
{
    /// <summary>
    /// Implementation of the <see cref="ICipherSuiteProvider"/> for QuantoCrypt.
    /// </summary>
    public sealed class QuantoCryptCipherSuiteProvider : ICipherSuiteProvider
    {
        public IReadOnlyList<ICipherSuite> SupportedCipherSuites { get; private set; }

        /// <summary>
        /// Dafault ctor, defines all supported <see cref="ICipherSuite"/>.
        /// </summary>
        public QuantoCryptCipherSuiteProvider()
        {
            SupportedCipherSuites = new List<ICipherSuite>()
            {
                new CrystalsKyber_CrystalsDilithium_Aes(),
                new CrystalsKyber_CrystalsDilithium_AesGcm()
            };
        }
    }
}
