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
    /// <see cref="KyberAlgorithm"/> with <see cref="KyberParameters.KYBER1024"/> + 
    /// <see cref="DilithiumAlgorithm"/> with <see cref="DilithiumParameters.DILITHIUM5"/> + 
    /// <see cref="AesAlgorithm"/>.
    /// </summary>
    /// <remarks>
    ///     The key for the <see cref="ISymmetricAlgorithm"/> should be of 256-bit size!
    /// </remarks>
    public sealed class CrystalsKyber1024_CrystalsDilithium5_Aes : ICipherSuite
    {
        public string Name => nameof(CrystalsKyber1024_CrystalsDilithium5_Aes);

        private KyberAlgorithm _kemAlgorithm;
        private DilithiumAlgorithm _dilithiumAlgorithm;
        private AesAlgorithm _symmetricAlgorithm;

        public IKEMAlgorithm GetKEMAlgorithm()
        {
            if (_kemAlgorithm == null)
                _kemAlgorithm = new KyberAlgorithm(KyberParameters.KYBER1024);

            return _kemAlgorithm;
        }

        public ISignatureAlgorithm GetSignatureAlgorithm(bool isForSigning)
        {
            if (_dilithiumAlgorithm == null)
                _dilithiumAlgorithm = new DilithiumAlgorithm(DilithiumParameters.DILITHIUM5, isForSigning);

            return _dilithiumAlgorithm;
        }

        public ISymmetricAlgorithm GetSymmetricAlgorithm(byte[] sessionKey)
        {
            if (sessionKey == null || sessionKey.Length != 32)
                throw new ArgumentOutOfRangeException(nameof(sessionKey), "The key should be of 256-bit size!");

            if (_symmetricAlgorithm == null)
                _symmetricAlgorithm = new AesAlgorithm(sessionKey);

            return _symmetricAlgorithm;
        }
    }
}
