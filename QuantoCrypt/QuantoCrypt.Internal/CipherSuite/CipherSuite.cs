using QuantoCrypt.Infrastructure.CipherSuite;

namespace QuantoCrypt.Internal.CipherSuite
{
    /// <summary>
    /// Collection of all supported <see cref="ICipherSuite"/>.
    /// </summary>
    /// <remarks>
    ///     In case of adding new inheritor of the <see cref="ICipherSuite"/>, this should also be expanded.
    /// </remarks>
    [Flags]
    public enum CipherSuite : ulong
    {
        None                                                        = 0,
        CrystalsKyber1024_CrystalsDilithium5_Aes                    = 1 << 0,
        CrystalsKyber1024_CrystalsDilithium5_AesGcm                 = 1 << 1,
        CrystalsKyber1024_CrystalsDilithium5Aes_Aes                 = 1 << 2,
        CrystalsKyber1024_CrystalsDilithium5Aes_AesGcm              = 1 << 3,
        CrystalsKyber1024Aes_CrystalsDilithium5_Aes                 = 1 << 4,
        CrystalsKyber1024Aes_CrystalsDilithium5_AesGcm              = 1 << 5,
        CrystalsKyber1024Aes_CrystalsDilithium5Aes_Aes              = 1 << 6,
        CrystalsKyber1024Aes_CrystalsDilithium5Aes_AesGcm           = 1 << 7
    }
}
