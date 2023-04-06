using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.KEM.CRYSTALS.Kyber;
using QuantoCrypt.Internal.Symmetric;

namespace QuantoCrypt.Internal.CipherSuite
{
    /// <summary>
    /// <see cref="KyberAlgorithm"/> with <see cref="KyberParameters.KYBER1024_AES"/> + [] + <see cref="AesAlgorithm"/>.
    /// </summary>
    public sealed class CrystalsKyber1024Aes_CrystalsDilithium_Aes : ICipherSuite
    {
        public string Name => nameof(CrystalsKyber1024Aes_CrystalsDilithium_Aes);

        private KyberAlgorithm _kemAlgorithm;
        private AesAlgorithm _symmetricAlgorithm;

        public IKEMAlgorithm GetKEMAlgorithm()
        {
            if (_kemAlgorithm == null)
                _kemAlgorithm = new KyberAlgorithm(KyberParameters.KYBER1024_AES);

            return _kemAlgorithm;
        }

        public ISignatureAlgorithm GetSignatureAlgorithm() => throw new NotImplementedException();

        public ISymmetricAlgorithm GetSymmetricAlgorithm(byte[] sessionKey)
        {
            if (_symmetricAlgorithm == null)
                _symmetricAlgorithm = new AesAlgorithm(sessionKey);

            return _symmetricAlgorithm;
        }
    }
}
