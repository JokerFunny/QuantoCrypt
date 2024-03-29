﻿using QuantoCrypt.Common;
using QuantoCrypt.Common.Parameters;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Handle all params for the CRYSTALS-Dilithium key generator.
    /// </summary>
    internal sealed class DilithiumKeyGenerationParameters : IKeyGenerationParameters
    {
        private const int _keyStrength = 256;

        private readonly DilithiumParameters _rDilithiumParameters;
        private readonly SecureRandom _rSecureRandom;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="random">Target <see cref="SecureRandom"/> to be used.</param>
        /// <param name="dilithiumParameters">Target <see cref="DilithiumParameters"/>.</param>
        internal DilithiumKeyGenerationParameters(SecureRandom random, DilithiumParameters dilithiumParameters)
        {
            _rSecureRandom = random;
            _rDilithiumParameters = dilithiumParameters;
        }

        /// <summary>
        /// Hadnle the params needed for Dilithium algo.
        /// </summary>
        internal DilithiumParameters Parameters => _rDilithiumParameters;

        public SecureRandom Random => _rSecureRandom;

        public int KeyStrength => _keyStrength;
    }
}
