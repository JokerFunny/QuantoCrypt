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
        public Guid Id { get; } = Guid.NewGuid();

        private readonly Socket _rSocket;
        private readonly Action<string> _rTraceAction;

        /// <remarks>
        ///     1 Mb buffer.
        /// </remarks>
        private readonly byte[] buffer = new byte[1048576];

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="socket">Target <see cref="Socket"/>, configured as a server or as a client.</param>
        /// <param name="debugAction">Target trace action that could be used to trace data.</param>
        public SocketTransportConnection(Socket socket, Action<string> debugAction = null)
        {
            _rSocket = socket;
            _rTraceAction = debugAction;
        }

        public byte[] Receive()
        {
            try
            {
                var read = _rSocket.Receive(buffer);

                byte[] result = new byte[read];
                Array.Copy(buffer, result, read);

                if (_rTraceAction != null)
                    _rTraceAction.Invoke($"Id [{Id}] - receive data:{Environment.NewLine}[version] - [{result[0]}]{Environment.NewLine}[message type] - [{result[1]}]" +
                        $"{Environment.NewLine}[data length] - [{result.Length}]{Environment.NewLine}[message integrity] - [{result[6]} {result[7]} {result[8]} {result[9]}]");

                return result;
            }
            catch(SocketException se)
            {
                if (_rTraceAction != null)
                    _rTraceAction.Invoke($"SocketException: [{se}]");

                throw;
            }
            catch (Exception e)
            {
                if (_rTraceAction != null)
                    _rTraceAction.Invoke($"Exception: [{e.Message}], stacktrace: [{e.StackTrace}].");

                throw;
            }
        }

        public int Send(byte[] data)
        {
            try
            {
                if (_rTraceAction != null)
                    _rTraceAction.Invoke($"Id [{Id}] - send data:{Environment.NewLine}[version] - [{data[0]}]{Environment.NewLine}[message type] - [{data[1]}]" +
                        $"{Environment.NewLine}[data length] - [{data.Length}]{Environment.NewLine}[message integrity] - [{data[6]} {data[7]} {data[8]} {data[9]}]");

                return _rSocket.Send(data);
            }
            catch (SocketException se)
            {
                if (_rTraceAction != null)
                    _rTraceAction.Invoke($"SocketException: [{se}]");

                throw;
            }
            catch (Exception e)
            {
                if (_rTraceAction != null)
                    _rTraceAction.Invoke($"Exception: [{e.Message}], stacktrace: [{e.StackTrace}].");

                throw;
            }
        }

        public void Dispose()
        {
            _rSocket?.Shutdown(SocketShutdown.Both);

            _rSocket?.Close();
        }

        public bool Close()
        {
            try
            {
                Dispose();

                return true;
            }
            catch (Exception e)
            {
                if (_rTraceAction != null)
                    _rTraceAction.Invoke($"Exception: [{e.Message}], stacktrace: [{e.StackTrace}].");
            }

            return false;
        }
    }
}
