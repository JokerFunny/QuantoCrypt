using QuantoCrypt.Infrastructure.CipherSuite;

namespace QuantoCrypt.Internal.CipherSuite
{
    /// <summary>
    /// Collection of all supported <see cref="ICipherSuite"/>.
    /// </summary>
    /// <remarks>
    ///     In case of adding new inheritor of the <see cref="ICipherSuite"/>, this should also be expanded.
    /// </remarks>
    public enum CipherSuite : byte
    {
        None,
        CrystalsKyber1024_CrystalsDilithium_Aes,
        CrystalsKyber1024_CrystalsDilithium_AesGcm,
        CrystalsKyber1024Aes_CrystalsDilithium_Aes,
        CrystalsKyber1024Aes_CrystalsDilithium_AesGcm
    }
}
