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
                new CrystalsKyber1024_CrystalsDilithium5_Aes(),
                new CrystalsKyber1024_CrystalsDilithium5_AesGcm(),
                new CrystalsKyber1024_CrystalsDilithium5Aes_Aes(),
                new CrystalsKyber1024_CrystalsDilithium5Aes_AesGcm(),
                new CrystalsKyber1024Aes_CrystalsDilithium5_Aes(),
                new CrystalsKyber1024Aes_CrystalsDilithium5_AesGcm(),
                new CrystalsKyber1024Aes_CrystalsDilithium5Aes_Aes(),
                new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm()
            };

        public IReadOnlyList<ICipherSuite> SupportedCipherSuites => _srSupportedCipherSuites;
    }
}
