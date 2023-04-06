namespace QuantoCrypt.Infrastructure.Connection
{
    /// <summary>
    /// The connection to be used as an end node (could be a server+client or independant).
    /// </summary>
    public interface ITransportConnection : IDisposable
    {
        /// <summary>
        /// Connection identificator.
        /// </summary>
        Guid Id { get; }

        /// <summary>
        /// Send target <paramref name="data"/> to the reviever.
        /// </summary>
        /// <param name="data">Target message.</param>
        /// <returns>
        ///     Amount of sent bytes.
        /// </returns>
        int Send(byte[] data);

        /// <summary>
        /// Receive data from sender.
        /// </summary>
        /// <returns>
        ///     Target data.
        /// </returns>
        byte[] Receive();
    }
}
