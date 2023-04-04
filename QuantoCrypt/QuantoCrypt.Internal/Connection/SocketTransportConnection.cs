using QuantoCrypt.Infrastructure.Connection;
using System.Net.Sockets;

namespace QuantoCrypt.Internal.Connection
{
    /// <summary>
    /// Implementation of <see cref="ITransportConnection"/> over <see cref="Socket"/>.
    /// </summary>
    public class SocketTransportConnection : ITransportConnection
    {
        public Guid Id => throw new NotImplementedException();

        private readonly Socket _rSocket;

        /// <remarks>
        ///     1 Mb buffer.
        /// </remarks>
        private readonly byte[] buffer = new byte[1048576];

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="socket">Target <see cref="Socket"/>, configured as a server or as a client.</param>
        public SocketTransportConnection(Socket socket)
        {
            _rSocket = socket;
        }

        public byte[] Recieve()
        {
            try
            {
                var read = _rSocket.Receive(buffer);

                byte[] result = new byte[read];
                Array.Copy(buffer, result, read);

                return buffer.AsSpan().ToArray();
            }
            catch
            {
                throw;
            }
        }

        public void Send(byte[] data)
        {
            try
            {
                _rSocket.Send(data);
            }
            catch
            {
                throw;
            }
        }
    }
}
