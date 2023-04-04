namespace QuantoCrypt.Infrastructure.Symmetric
{
    /// <summary>
    /// Interface for all symmetric algorithms that would be used to encrypt data.
    /// </summary>
    public interface ISymmetricAlgorithm : IAlgorithm
    {
        /// <summary>
        /// Encrypt target <paramref name="plainText"/> using symmetric encryption.
        /// </summary>
        /// <param name="plainText">Target plain text to be encrypted.</param>
        /// <returns>
        ///     Encrypted text.
        /// </returns>
        byte[] Encrypt(byte[] plainText);

        /// <summary>
        /// Decrypts target <paramref name="cipherText"/> using symmetric encryption.
        /// </summary>
        /// <param name="cipherText">Target encrypted text.</param>
        /// <returns>
        ///     Decrypted text.
        /// </returns>
        byte[] Decrypt(byte[] cipherText);
    }
}
