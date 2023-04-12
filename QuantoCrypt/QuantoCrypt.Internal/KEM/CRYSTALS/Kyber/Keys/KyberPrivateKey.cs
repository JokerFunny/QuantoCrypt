using QuantoCrypt.Internal.Utilities;

namespace QuantoCrypt.Internal.KEM.CRYSTALS.Kyber
{
    /// <summary>
    /// Handle work with CRYSTALS-Kyber private key.
    /// </summary>
    internal sealed class KyberPrivateKey : KyberKey
    {
        private readonly byte[] _rS;
        private readonly byte[] _rHpk;
        private readonly byte[] _rNonce;
        private readonly byte[] _rT;
        private readonly byte[] _rRho;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="parameters">Target <see cref="KyberParameters"/>.</param>
        /// <param name="s">Target [IndCpaSecretKey] private key.</param>
        /// <param name="hpk">Hashed public key.</param>
        /// <param name="nonce">Target nonce.</param>
        /// <param name="t">First part of the public key [0, IndCpaPublicKeyBytes - 32].</param>
        /// <param name="rho">Second part of the public key [IndCpaPublicKeyBytes - 32, IndCpaPublicKeyBytes].</param>
        internal KyberPrivateKey(KyberParameters parameters, byte[] s, byte[] hpk, byte[] nonce, byte[] t, byte[] rho)
            : base(true, parameters)
        {
            _rS = (byte[])s.Clone();
            _rHpk = (byte[])hpk.Clone();
            _rNonce = (byte[])nonce.Clone();
            _rT = (byte[])t.Clone();
            _rRho = (byte[])rho.Clone();
        }

        public override byte[] GetEncoded()
            => ArrayUtilities.Combine(_rS, _rT, _rRho, _rHpk, _rNonce);

        internal byte[] S => _rS;
        internal byte[] Hpk => _rHpk;
        internal byte[] Nonce => _rNonce;
        internal byte[] T => _rT;
        internal byte[] Rho => _rRho;
    }
}
