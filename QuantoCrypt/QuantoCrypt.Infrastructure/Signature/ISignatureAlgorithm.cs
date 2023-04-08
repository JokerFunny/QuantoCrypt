using QuantoCrypt.Infrastructure.Common;

namespace QuantoCrypt.Infrastructure.Signature
{
    /// <summary>
    /// Interface for all signature algorithms that would be used to authenticate users.
    /// </summary>
    public interface ISignatureAlgorithm : IAlgorithm
    {
        /// <summary>
        /// Generate the public + private key.
        /// </summary>
        /// <returns>
        ///     Public + private keys.
        /// </returns>
        AsymmetricKeyPair KeyGen();

        /// <summary>
        /// Generate the signature over <paramref name="message"/> using privateKey.
        /// </summary>
        /// <param name="message">Target message to be signed.</param>
        /// <returns>
        ///     Generated signature.
        /// </returns>
        byte[] Sign(byte[] message);

        /// <summary>
        /// Verify that the provided signature is valid.
        /// </summary>
        /// <param name="publicKey">Target public key.</param>
        /// <param name="message">Targe message that was used to generate the signature.</param>
        /// <param name="signature">Target signature to be validated.</param>
        /// <returns>
        ///     True in case if signature is valid, otherwise - false.
        /// </returns>
        bool Verify(byte[] publicKey, byte[] message, byte[] signature);
    }
}
