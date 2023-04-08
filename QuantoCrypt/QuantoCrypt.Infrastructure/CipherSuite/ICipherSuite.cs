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
        /// Method to get target <see cref="IKEMAlgorithm"/>.
        /// </summary>
        IKEMAlgorithm GetKEMAlgorithm();

        /// <summary>
        /// Method to get target <see cref="ISignatureAlgorithm"/>.
        /// </summary>
        /// <param name="isForSigning">If <see cref="ISignatureAlgorithm"/> should sign or verify messages.</param>
        ISignatureAlgorithm GetSignatureAlgorithm(bool isForSigning);

        /// <summary>
        /// Method to get target <see cref="ISymmetricAlgorithm"/>.
        /// </summary>
        ISymmetricAlgorithm GetSymmetricAlgorithm(byte[] sessionKey);
    }
}
