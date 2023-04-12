namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Parameters for the CRYSTALS-KYBER KEM algorithm.
    /// </summary>
    public sealed class KyberParameters
    {
        // with Shake symmetric encription.
        public static KyberParameters KYBER512 = new KyberParameters("kyber512", 2, 128, false);
        public static KyberParameters KYBER768 = new KyberParameters("kyber768", 3, 192, false);
        public static KyberParameters KYBER1024 = new KyberParameters("kyber1024", 4, 256, false);

        // with AES symmetric encription.
        public static KyberParameters KYBER512_AES = new KyberParameters("kyber512-aes", 2, 128, true);
        public static KyberParameters KYBER768_AES = new KyberParameters("kyber768-aes", 3, 192, true);
        public static KyberParameters KYBER1024_AES = new KyberParameters("kyber1024-aes", 4, 256, true);

        private readonly string _rName;
        private readonly int _rSessionKeySize;
        private readonly KyberEngine _rEngine;

        private KyberParameters(string name, int k, int sessionKeySize, bool usingAes)
        {
            _rName = name;
            _rSessionKeySize = sessionKeySize;
            _rEngine = new KyberEngine(k, usingAes);
        }

        /// <summary>
        /// Name of the selected algorithm.
        /// </summary>
        public string Name => _rName;

        /// <summary>
        /// Use matrices and vectors of small dimension k × l over Zq[X]/(X^256 + 1) as a part of the SIS.
        /// </summary>
        /// <remarks>
        ///     Scale security levels by varying k.
        /// </remarks>
        public int K => _rEngine.K;

        /// <summary>
        /// Size of the session key.
        /// </summary>
        public int SessionKeySize => _rSessionKeySize;

        /// <summary>
        /// Target <see cref="KyberEngine"/>.
        /// </summary>
        internal KyberEngine Engine => _rEngine;
    }
}
