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
    public enum CipherSuite : byte
    {
        None                                                        = 0,
        CrystalsKyber1024_CrystalsDilithium_Aes                     = 1 << 0,
        CrystalsKyber1024_CrystalsDilithium_AesGcm                  = 1 << 1,
        CrystalsKyber1024Aes_CrystalsDilithium_Aes                  = 1 << 2,
        CrystalsKyber1024Aes_CrystalsDilithium_AesGcm               = 1 << 3
    }
}
