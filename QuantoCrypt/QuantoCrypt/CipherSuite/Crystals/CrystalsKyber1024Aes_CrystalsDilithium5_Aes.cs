using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.KEM.CRYSTALS.Kyber;
using QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium;
using QuantoCrypt.Internal.Symmetric;

namespace QuantoCrypt.Internal.CipherSuite
{
    /// <summary>
    /// <see cref="KyberAlgorithm"/> with <see cref="KyberParameters.KYBER1024_AES"/> + 
    /// <see cref="DilithiumAlgorithm"/> with <see cref="DilithiumParameters.DILITHIUM5"/> + 
    /// <see cref="AesAlgorithm"/>.
    /// </summary>
    /// <remarks>
    ///     The key for the <see cref="ISymmetricAlgorithm"/> should be of 256-bit size!
    /// </remarks>
    public sealed class CrystalsKyber1024Aes_CrystalsDilithium5_Aes : ICipherSuite
    {
        public string Name => nameof(CrystalsKyber1024Aes_CrystalsDilithium5_Aes);

        public IKEMAlgorithm GetKEMAlgorithm()
            => new KyberAlgorithm(KyberParameters.KYBER1024_AES);

        public ISignatureAlgorithm GetSignatureAlgorithm(bool isForSigning)
            => new DilithiumAlgorithm(DilithiumParameters.DILITHIUM5, isForSigning);

        public ISymmetricAlgorithm GetSymmetricAlgorithm(byte[] sessionKey)
        {
            if (sessionKey == null || sessionKey.Length != 32)
                throw new ArgumentOutOfRangeException(nameof(sessionKey), "The key should be of 256-bit size!");

            return new AesAlgorithm(sessionKey);
        }
    }
}
