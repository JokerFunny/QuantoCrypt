using QuantoCrypt.Infrastructure.Connection;
using System.Net;
using System.Net.Sockets;

namespace QuantoCrypt.Internal.Connection
{
    /// <summary>
    /// Implementation of <see cref="ITransportConnection"/> over <see cref="Socket"/>.
    /// </summary>
    public class SocketTransportConnection : ITransportConnection
    {
        public Guid Id { get; } = Guid.NewGuid();

        /// <summary>
        /// Maximum size of the single message that could be proceeded.
        /// </summary>
        /// <remarks>
        ///     1 Mb. In case if the message would be longer - it need to be splited.
        /// </remarks>
        public const int BufferSize = 1048576;

        private readonly Socket _rSocket;
        private readonly bool _rIsServer;
        private readonly Action<string> _rTraceAction;
        private readonly bool _rExtendedLogs;

        /// <remarks>
        ///     1 Mb buffer.
        /// </remarks>
        private readonly byte[] _rReadBuffer = new byte[BufferSize];

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="socket">Target <see cref="Socket"/>, configured as a server or as a client.</param>
        /// <param name="debugAction">Target trace action that could be used to trace data.</param>
        /// <param name="extendedLogs">If extended logs with body message should be passed to <paramref name="debugAction"/>.</param>
        public SocketTransportConnection(Socket socket, Action<string> debugAction = null, bool extendedLogs = false)
        {
            _rSocket = socket;
            _rTraceAction = debugAction;
            _rExtendedLogs = extendedLogs;
        }

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="socket">Target <see cref="Socket"/>, configured as a server or as a client.</param>
        /// <param name="isServer">Is this a server or client connection.</param>
        /// <param name="debugAction">Target trace action that could be used to trace data.</param>
        SocketTransportConnection(Socket socket, bool isServer, Action<string> debugAction = null)
        {
            _rSocket = socket;
            _rIsServer = isServer;
            _rTraceAction = debugAction;
        }

        /// <summary>
        /// Creates a new ITransportConnection instance to handle an incoming connection for servers, return this - for clients.
        /// </summary>
        /// <remarks>
        ///     Should be called on server instance if created via <see cref="CreateDefaultServer"/>.
        /// </remarks>
        /// <returns>
        ///     A new ITransportConnection instance for server, this - for client.
        /// </returns>
        public ITransportConnection Connect()
        {
            if (_rIsServer)
                return new SocketTransportConnection(_rSocket.Accept(), true, _rTraceAction);

            return this;
        }

        public byte[] Receive()
        {
            try
            {
                List<byte> bufferMessage = new List<byte>();
                int read = -1;
                do
                {
                    read = _rSocket.Receive(_rReadBuffer);
                    bufferMessage.AddRange(_rReadBuffer[..read]);
                }
                while (read == BufferSize);

                byte[] result = bufferMessage.ToArray();

                /*var read = _rSocket.Receive(_rReadBuffer);

                byte[] result = new byte[read];
                Array.Copy(_rReadBuffer, result, read);*/

                ConnectionTraceHelper.sTraceMessageIfNeeded(Id, result, "receive", _rTraceAction, _rExtendedLogs);

                return result;
            }
            catch(SocketException se)
            {
                _rTraceAction?.Invoke($"SocketException: [{se}]");

                throw;
            }
            catch (Exception e)
            {
                _rTraceAction?.Invoke($"Exception: [{e.Message}], stacktrace: [{e.StackTrace}].");

                throw;
            }
        }

        public int Send(byte[] data)
        {
            try
            {
                ConnectionTraceHelper.sTraceMessageIfNeeded(Id, data, "send", _rTraceAction, _rExtendedLogs);

                return _rSocket.Send(data);
            }
            catch (SocketException se)
            {
                _rTraceAction?.Invoke($"SocketException: [{se}]");

                throw;
            }
            catch (Exception e)
            {
                _rTraceAction?.Invoke($"Exception: [{e.Message}], stacktrace: [{e.StackTrace}].");

                throw;
            }
        }

        public Task<int> SendAsync(byte[] data)
        {
            try
            {
                ConnectionTraceHelper.sTraceMessageIfNeeded(Id, data, "send", _rTraceAction, _rExtendedLogs);

                return _rSocket.SendAsync(data);
            }
            catch (SocketException se)
            {
                _rTraceAction?.Invoke($"SocketException: [{se}]");

                throw;
            }
            catch (Exception e)
            {
                _rTraceAction?.Invoke($"Exception: [{e.Message}], stacktrace: [{e.StackTrace}].");

                throw;
            }
        }

        public async Task<byte[]> ReceiveAsync()
        {
            try
            {
                List<byte> bufferMessage = new List<byte>();
                int read = -1;
                do
                {
                    read = await _rSocket.ReceiveAsync(_rReadBuffer);
                    bufferMessage.AddRange(_rReadBuffer[..read]);
                }
                while (read == BufferSize);

                byte[] result = bufferMessage.ToArray();

                /*var read = await _rSocket.ReceiveAsync(_rReadBuffer);

                byte[] result = new byte[read];
                Array.Copy(_rReadBuffer, result, read);*/

                ConnectionTraceHelper.sTraceMessageIfNeeded(Id, result, "receive", _rTraceAction, _rExtendedLogs);

                return result;
            }
            catch (SocketException se)
            {
                _rTraceAction?.Invoke($"SocketException: [{se}]");

                throw;
            }
            catch (Exception e)
            {
                _rTraceAction?.Invoke($"Exception: [{e.Message}], stacktrace: [{e.StackTrace}].");

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

        /// <summary>
        /// Create a default client connection.
        /// </summary>
        /// <param name="addressFamily">Target <see cref="AddressFamily"/>.</param>
        /// <param name="targetEndPoint">Target <see cref="EndPoint"/> address to connect to.</param>
        /// <param name="debugAction">Target trace action that could be used to trace data.</param>
        /// <returns>
        ///     Initialized <see cref="SocketTransportConnection"/>.
        /// </returns>
        public static SocketTransportConnection CreateDefaultServer(AddressFamily addressFamily, EndPoint targetEndPoint, Action<string> debugAction = null)
        {
            Socket server = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            
            // A Socket must be associated with an endpoint using the Bind method
            server.Bind(targetEndPoint);
            
            // Specify how many requests a Socket can listen before it gives Server busy response.
            // We will listen 10 requests at a time
            server.Listen(10);

            server.ReceiveBufferSize = BufferSize;
            //server.SendBufferSize = BufferSize;

            return new SocketTransportConnection(server, true, debugAction);
        }

        /// <summary>
        /// Create a default client connection.
        /// </summary>
        /// <param name="addressFamily">Target <see cref="AddressFamily"/>.</param>
        /// <param name="targetEndPoint">Target <see cref="EndPoint"/> address to connect to.</param>
        /// <param name="debugAction">Target trace action that could be used to trace data.</param>
        /// <returns>
        ///     Initialized <see cref="SocketTransportConnection"/>.
        /// </returns>
        public static SocketTransportConnection CreateDefaultClient(AddressFamily addressFamily, EndPoint targetEndPoint, Action<string> debugAction = null)
        {
            Socket client = new Socket(addressFamily, SocketType.Stream, ProtocolType.Tcp);
            
            client.Connect(targetEndPoint);

            return new SocketTransportConnection(client, false, debugAction);
        }
    }
}
