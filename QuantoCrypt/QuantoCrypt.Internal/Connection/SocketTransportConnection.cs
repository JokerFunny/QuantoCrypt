using QuantoCrypt.Infrastructure.Connection;
using System.Net.Sockets;
using System.Text;

namespace QuantoCrypt.Internal.Connection
{
    /// <summary>
    /// Implementation of <see cref="ITransportConnection"/> over <see cref="Socket"/>.
    /// </summary>
    public class SocketTransportConnection : ITransportConnection
    {
        public Guid Id => Guid.NewGuid();

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

        public byte[] Receive()
        {
            try
            {
                var read = _rSocket.Receive(buffer);

                byte[] result = new byte[read];
                Array.Copy(buffer, result, read);

                Console.WriteLine($"Id {Id} - receive data: {Encoding.ASCII.GetString(result)}");

                return result;
            }
            catch(SocketException se)
            {
                Console.WriteLine("SocketException : {0}", se.ToString());
                throw;
            }
            catch (Exception e)
            {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
                throw;
            }
        }

        public int Send(byte[] data)
        {
            try
            {
                Console.WriteLine($"Id {Id} - send data: {Encoding.ASCII.GetString(data)}");

                return _rSocket.Send(data);
            }
            catch (SocketException se)
            {
                Console.WriteLine("SocketException : {0}", se.ToString());
                throw;
            }
            catch (Exception e)
            {
                Console.WriteLine("Unexpected exception : {0}", e.ToString());
                throw;
            }
        }

        public void Dispose()
        {
            _rSocket?.Shutdown(SocketShutdown.Both);

            _rSocket?.Close();
        }
    }
}
