namespace QuantoCrypt.Infrastructure.Connection
{
    /// <summary>
    /// The secure connection to be used as an end node (could be a server+client or independant).
    /// </summary>
    public interface ISecureTransportConnection : ITransportConnection
    {
        /// <summary>
        /// Send target <paramref name="data"/> to the reviever using symmetric encryption.
        /// </summary>
        /// <param name="data">Target message, would be encrypted.</param>
        /// <returns>
        ///     Amount of sent bytes.
        /// </returns>
        new int Send(byte[] data);

        /// <summary>
        /// Receive encrypted data from sender, decryp it using symmetric algorithm.
        /// </summary>
        /// <returns>
        ///     Decrypted data.
        /// </returns>
        new byte[] Receive();

        /// <summary>
        /// Asynchronously send target <paramref name="data"/> to the reviever using symmetric encryption.
        /// </summary>
        /// <param name="data">Target message, would be encrypted.</param>
        /// <returns>
        ///     Amount of sent bytes.
        /// </returns>
        new Task<int> SendAsync(byte[] data);

        /// <summary>
        /// Asynchronously receive encrypted data from sender, decryp it using symmetric algorithm.
        /// </summary>
        /// <returns>
        ///     Decrypted data.
        /// </returns>
        new Task<byte[]> ReceiveAsync();
    }
}
