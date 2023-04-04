namespace QuantoCrypt.Infrastructure.Connection
{
    /// <summary>
    /// The connection to be used as an end node (could be a server+client or independant).
    /// </summary>
    public interface ITransportConnection
    {
        /// <summary>
        /// Connection identificator.
        /// </summary>
        Guid Id { get; }

        /// <summary>
        /// Send target <paramref name="data"/> to the reviever.
        /// </summary>
        /// <param name="data">Target message.</param>
        void Send(byte[] data);

        /// <summary>
        /// Recieve data from sender.
        /// </summary>
        /// <returns>
        ///     Target data.
        /// </returns>
        byte[] Recieve();
    }
}
