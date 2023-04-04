using QuantoCrypt.Infrastructure.KEM;
using QuantoCrypt.Infrastructure.Signature;
using QuantoCrypt.Infrastructure.Symmetric;

namespace QuantoCrypt.Infrastructure.CipherSuite
{
    /// <summary>
    /// Represent the cipher suite that contains <see cref="IKEMAlgorithm"/> + <see cref="ISignatureAlgorithm"/> + <see cref="ISymmetricAlgorithm"/>.
    /// </summary>
    public interface ICipherSuite
    {
        /// <summary>
        /// Name of the cipher suite.
        /// </summary>
        string Name { get; }

        /// <summary>
        /// Target <see cref="IKEMAlgorithm"/>.
        /// </summary>
        IKEMAlgorithm KEMAlgorithm { get; }

        /// <summary>
        /// Target <see cref="ISignatureAlgorithm"/>.
        /// </summary>
        ISignatureAlgorithm SignatureAlgorithm { get; }

        /// <summary>
        /// Target <see cref="ISymmetricAlgorithm"/>.
        /// </summary>
        ISymmetricAlgorithm SymmetricAlgorithm { get; }
    }
}
