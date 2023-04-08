using QuantoCrypt.Infrastructure.Common;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Handle all params for the CRYSTALS-Kyber key generator.
    /// </summary>
    public sealed class KyberKeyGenerationParameters : IKeyGenerationParameters
    {
        private const int _keyStrength = 256;

        private readonly KyberParameters _rKyberParameters;
        private readonly SecureRandom _rSecureRandom;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="random">Target <see cref="SecureRandom"/> to be used.</param>
        /// <param name="kyberParameters">Target <see cref="KyberParameters"/>.</param>
        public KyberKeyGenerationParameters(SecureRandom random, KyberParameters kyberParameters)
        {
            _rSecureRandom = random;
            _rKyberParameters = kyberParameters;
        }

        /// <summary>
        /// Hadnle the params needed for Kyber algo.
        /// </summary>
        public KyberParameters Parameters => _rKyberParameters;

        public SecureRandom Random => _rSecureRandom;

        public int KeyStrength => _keyStrength;
    }
}
