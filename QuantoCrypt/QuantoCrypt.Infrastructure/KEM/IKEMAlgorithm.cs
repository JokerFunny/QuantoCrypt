﻿using QuantoCrypt.Infrastructure.Common;

namespace QuantoCrypt.Infrastructure.KEM
{
    /// <summary>
    /// Interface for all Key encapsulation mechanism algorithms that would be used to establish a single secret session key.
    /// </summary>
    public interface IKEMAlgorithm : IAlgorithm
    {
        /// <summary>
        /// Generate the public + private key <see cref="AsymmetricKeyPair"/>.
        /// </summary>
        /// <returns>
        ///     Public + private keys <see cref="AsymmetricKeyPair"/>.
        /// </returns>
        AsymmetricKeyPair KeyGen();

        /// <summary>
        /// Generate the <see cref="ISecretWithEncapsulation"/> using clients' PK.
        /// </summary>
        /// <param name="publicKey">Target public key to be used.</param>
        /// <returns>
        ///     <see cref="ISecretWithEncapsulation"/>.
        /// </returns>
        ISecretWithEncapsulation Encaps(byte[] publicKey);

        /// <summary>
        /// Get the session key from the <paramref name="cipherText"/> using privateKey.
        /// </summary>
        /// <param name="cipherText">Cipher text as a result of the <see cref="Encaps(byte[])"/> operation.</param>
        /// <remarks>
        ///     Uses private key generated during <see cref="KeyGen()"/>.
        /// </remarks>
        /// <returns>
        ///     Session key.
        /// </returns>
        byte[] Decaps(byte[] cipherText);
    }
}
