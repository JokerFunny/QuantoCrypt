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

        public IKEMAlgorithm KEMAlgorithm => throw new NotImplementedException();

        public ISignatureAlgorithm SignatureAlgorithm => throw new NotImplementedException();

        public ISymmetricAlgorithm SymmetricAlgorithm => _rSymmetricAlgorithmCreator.Invoke(SessionKey);

        public byte[] SessionKey { get; set; }

        private readonly Func<byte[], ISymmetricAlgorithm> _rSymmetricAlgorithmCreator = (byte[] key) => new AesGcmAlgorithm(key);
    }
}
