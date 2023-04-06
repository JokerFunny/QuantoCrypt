using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.KEM.CRYSTALS.Kyber;
using QuantoCrypt.Internal.Symmetric;

namespace QuantoCrypt.Internal.CipherSuite
{
    /// <summary>
    /// <see cref="KyberAlgorithm"/> with <see cref="KyberParameters.KYBER1024"/> + [] + <see cref="AesGcmAlgorithm"/>.
    /// </summary>
    public sealed class CrystalsKyber1024_CrystalsDilithium_AesGcm : ICipherSuite
    {
        public string Name => nameof(CrystalsKyber1024_CrystalsDilithium_AesGcm);

        private KyberAlgorithm _kemAlgorithm;
        private AesGcmAlgorithm _symmetricAlgorithm;

        public IKEMAlgorithm GetKEMAlgorithm()
        {
            if (_kemAlgorithm == null)
                _kemAlgorithm = new KyberAlgorithm(KyberParameters.KYBER1024);

            return _kemAlgorithm;
        }

        public ISignatureAlgorithm GetSignatureAlgorithm() => throw new NotImplementedException();

        public ISymmetricAlgorithm GetSymmetricAlgorithm(byte[] sessionKey)
        {
            if (_symmetricAlgorithm == null)
                _symmetricAlgorithm = new AesGcmAlgorithm(sessionKey);

            return _symmetricAlgorithm;
        }
    }
}
