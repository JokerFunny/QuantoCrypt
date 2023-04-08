using QuantoCrypt.Infrastructure.Common;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Parameters for the CRYSTALS-DILITHIUM DS algorithm.
    /// </summary>
    public sealed class DilithiumParameters
    {
        // with Shake symmetric encription.
        public static DilithiumParameters DILITHIUM2 = new DilithiumParameters(2, false);
        public static DilithiumParameters DILITHIUM3 = new DilithiumParameters(3, false);
        public static DilithiumParameters DILITHIUM5 = new DilithiumParameters(5, false);

        // with AES symmetric encription.
        public static DilithiumParameters DILITHIUM2_AES = new DilithiumParameters(2, true);
        public static DilithiumParameters DILITHIUM3_AES = new DilithiumParameters(3, true);
        public static DilithiumParameters DILITHIUM5_AES = new DilithiumParameters(5, true);

        private readonly int _rSecurityLevel;
        private readonly bool _rUsingAes;

        private DilithiumParameters(int param, bool usingAes)
        {
            _rSecurityLevel = param;
            _rUsingAes = usingAes;
        }

        /// <summary>
        /// Get target <see cref="DilithiumEngine"/> by <paramref name="random"/> and private params.
        /// </summary>
        /// <param name="random">Target <see cref="SecureRandom"/>.</param>
        /// <returns>
        ///     Target <see cref="DilithiumEngine"/>.
        /// </returns>
        internal DilithiumEngine GetEngine(SecureRandom random)
        {
            return new DilithiumEngine(_rSecurityLevel, random, _rUsingAes);
        }
    }
}
