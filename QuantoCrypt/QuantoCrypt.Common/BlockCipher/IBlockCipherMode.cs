﻿namespace QuantoCrypt.Common.BlockCipher
{
    /// <summary>
    /// Interface for any mode, used by Block cipher.
    /// </summary>
    public interface IBlockCipherMode : IBlockCipher
    {
        /// <summary>
        /// Return the <code cref="IBlockCipher"/> underlying this cipher mode.
        /// </summary>
        IBlockCipher UnderlyingCipher { get; }

        /// <summary>
        /// Indicates whether this cipher mode can handle partial blocks.
        /// </summary>
        bool IsPartialBlockOkay { get; }

        /// <summary>
        /// Reset the cipher mode to the same state as it was after the last init (if there was one).
        /// </summary>
        void Reset();
    }
}
