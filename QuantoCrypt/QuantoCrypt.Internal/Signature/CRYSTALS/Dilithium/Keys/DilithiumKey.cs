using QuantoCrypt.Infrastructure.Common;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Handle work with CRYSTALS-Dilithium keys.
    /// </summary>
    internal abstract class DilithiumKey : AsymmetricKey
    {
        private readonly DilithiumParameters _rDilithiumParameters;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="isPrivate">Determines if target key is private or not.</param>
        /// <param name="parameters">Target <see cref="DilithiumParameters"/>.</param>
        internal DilithiumKey(bool isPrivate, DilithiumParameters parameters)
            : base(isPrivate)
        {
            _rDilithiumParameters = parameters;
        }

        /// <summary>
        /// Target <see cref="DilithiumParameters"/> attached to this key.
        /// </summary>
        internal DilithiumParameters Parameters => _rDilithiumParameters;
    }
}
