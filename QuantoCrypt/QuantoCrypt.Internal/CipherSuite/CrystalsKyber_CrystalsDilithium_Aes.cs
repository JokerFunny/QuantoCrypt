using QuantoCrypt.Infrastructure.CipherSuite;
using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using QuantoCrypt.Infrastructure.Symmetric;
using QuantoCrypt.Internal.Symmetric;

namespace QuantoCrypt.Internal.CipherSuite
{
    public sealed class CrystalsKyber_CrystalsDilithium_Aes : ICipherSuite
    {
        public string Name => nameof(CrystalsKyber_CrystalsDilithium_Aes);

        public IKEMAlgorithm KEMAlgorithm => throw new NotImplementedException();

        public ISignatureAlgorithm SignatureAlgorithm => throw new NotImplementedException();

        public ISymmetricAlgorithm SymmetricAlgorithm => _rSymmetricAlgorithmCreator.Invoke(SessionKey);

        public string? SessionKey { get; set; }

        private readonly Func<string, ISymmetricAlgorithm> _rSymmetricAlgorithmCreator = (string key) => new AesAlgorithm(key);
    }
}
