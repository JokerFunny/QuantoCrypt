using QuantoCrypt.Infrastructure.Common;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Handle work with CRYSTALS-Kyber keys.
    /// </summary>
    public abstract class KyberKey : AsymmetricKey
    {
        private readonly KyberParameters _rKyberParameters;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="isPrivate">Determines if target key is private or not.</param>
        /// <param name="parameters">Target <see cref="KyberParameters"/>.</param>
        internal KyberKey(bool isPrivate, KyberParameters parameters) 
            : base(isPrivate)
        {
            _rKyberParameters = parameters;
        }

        /// <summary>
        /// Target <see cref="KyberParameters"/> attached to this key.
        /// </summary>
        public KyberParameters Parameters => _rKyberParameters;
    }
}
