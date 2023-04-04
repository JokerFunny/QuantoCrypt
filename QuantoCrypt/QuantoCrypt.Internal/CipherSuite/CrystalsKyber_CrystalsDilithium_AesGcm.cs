using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.Symmetric;

namespace QuantoCrypt.Internal.CipherSuite
{
    public sealed class CrystalsKyber_CrystalsDilithium_AesGcm : ICipherSuite
    {
        public string Name => nameof(CrystalsKyber_CrystalsDilithium_AesGcm);

        public IKEMAlgorithm GetKEMAlgorithm() => throw new NotImplementedException();

        public ISignatureAlgorithm GetSignatureAlgorithm() => throw new NotImplementedException();

        public ISymmetricAlgorithm GetSymmetricAlgorithm(byte[] sessionKey) => new AesGcmAlgorithm(sessionKey);
    }
}
