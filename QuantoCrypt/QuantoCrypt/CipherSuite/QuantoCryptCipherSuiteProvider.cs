using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Internal.CipherSuite;

namespace QuantoCrypt.Internal.CipherSuite
{
    /// <summary>
    /// Implementation of the <see cref="ICipherSuiteProvider"/> for QuantoCrypt.
    /// </summary>
    public sealed class QuantoCryptCipherSuiteProvider : ICipherSuiteProvider
    {
        private static readonly Dictionary<ICipherSuite, ulong> _srSupportedCipherSuites = new Dictionary<ICipherSuite, ulong>()
            {
                { new CrystalsKyber1024_CrystalsDilithium5_Aes(), 1 << 0 },
                { new CrystalsKyber1024_CrystalsDilithium5_AesGcm(), 1 << 1 },
                { new CrystalsKyber1024_CrystalsDilithium5Aes_Aes(), 1 << 2 },
                { new CrystalsKyber1024_CrystalsDilithium5Aes_AesGcm(), 1 << 3 },
                { new CrystalsKyber1024Aes_CrystalsDilithium5_Aes(), 1 << 4 },
                { new CrystalsKyber1024Aes_CrystalsDilithium5_AesGcm(), 1 << 5 },
                { new CrystalsKyber1024Aes_CrystalsDilithium5Aes_Aes(), 1 << 6 },
                { new CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm(), 1 << 7 }
            };

        public IReadOnlyDictionary<ICipherSuite, ulong> SupportedCipherSuites => _srSupportedCipherSuites;
    }
}
