using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Internal.CipherSuite;

namespace QuantoCrypt.CipherSuites
{
    /// <summary>
    /// Implementation of the <see cref="ICipherSuiteProvider"/> for QuantoCrypt.
    /// </summary>
    public sealed class QuantoCryptCipherSuiteProvider : ICipherSuiteProvider
    {
        private static readonly List<ICipherSuite> _srSupportedCipherSuites = new List<ICipherSuite>()
            {
                new CrystalsKyber1024_CrystalsDilithium_Aes(),
                new CrystalsKyber1024_CrystalsDilithium_AesGcm(),
                new CrystalsKyber1024Aes_CrystalsDilithium_Aes(),
                new CrystalsKyber1024Aes_CrystalsDilithium_AesGcm()
            };

        public IReadOnlyList<ICipherSuite> SupportedCipherSuites => _srSupportedCipherSuites;
    }
}
