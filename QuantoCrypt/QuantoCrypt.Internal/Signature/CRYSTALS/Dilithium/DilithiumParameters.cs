using QuantoCrypt.Infrastructure.Common;

namespace QuantoCrypt.Internal.Signature.CRYSTALS.Dilithium
{
    /// <summary>
    /// Parameters for the CRYSTALS-DILITHIUM DS algorithm.
    /// </summary>
    public sealed class DilithiumParameters
    {
        // with Shake symmetric encription.
        public static DilithiumParameters DILITHIUM2 = new DilithiumParameters("dilithium2", 2, false);
        public static DilithiumParameters DILITHIUM3 = new DilithiumParameters("dilithium3", 3, false);
        public static DilithiumParameters DILITHIUM5 = new DilithiumParameters("dilithium5", 5, false);

        // with AES symmetric encription.
        public static DilithiumParameters DILITHIUM2_AES = new DilithiumParameters("dilithium2-aes", 2, true);
        public static DilithiumParameters DILITHIUM3_AES = new DilithiumParameters("dilithium3-aes", 3, true);
        public static DilithiumParameters DILITHIUM5_AES = new DilithiumParameters("dilithium5-aes", 5, true);

        private readonly string _rName;
        private readonly int _rSecurityLevel;
        private readonly bool _rUsingAes;

        private DilithiumParameters(string name, int param, bool usingAes)
        {
            _rName = name;
            _rSecurityLevel = param;
            _rUsingAes = usingAes;
        }

        /// <summary>
        /// Name of the selected algorithm.
        /// </summary>
        public string Name => _rName;

        /// <summary>
        /// Get target <see cref="DilithiumEngine"/> by <paramref name="random"/> and private params.
        /// </summary>
        /// <param name="random">Target <see cref="SecureRandom"/>.</param>
        /// <returns>
        ///     Target <see cref="DilithiumEngine"/>.
        /// </returns>
        internal DilithiumEngine GetEngine(SecureRandom random)
            => new DilithiumEngine(_rSecurityLevel, random, _rUsingAes);
    }
}
