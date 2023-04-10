﻿using QuantoCrypt.Internal.Message;
using System.Text;

namespace QuantoCrypt.Internal.Connection
{
    /// <summary>
    /// Helper to trace result of the connection data transfer operations.
    /// </summary>
    internal static class ConnectionTraceHelper
    {
        private static StringBuilder _sResultBuilder = new StringBuilder();
        private static StringBuilder _sPartBuilder = new StringBuilder();

        /// <summary>
        /// 
        /// </summary>
        /// <param name="targetData"></param>
        /// <param name="dataType"></param>
        /// <param name="traceAction"></param>
        /// <param name="extendedLogs"></param>
        internal static void sTraceMessageIfNeeded(Guid connectionId, byte[] targetData, string dataType, Action<string> traceAction, bool extendedLogs = false)
        {
            if (traceAction != null)
            {
                _sResultBuilder.Clear();

                _sResultBuilder.AppendLine($"Id [{connectionId}] - [{dataType}] data:");
                _sResultBuilder.AppendLine("Header:");
                _sResultBuilder.AppendLine($"0 - version - [{targetData[0]}];");
                _sResultBuilder.AppendLine($"1 - message type - [{targetData[1]}];");
                _sResultBuilder.AppendLine($"2 - 5 - message length [{targetData.Length}] - [{_sGetArrayAsString(targetData[2..6])}];");
                _sResultBuilder.AppendLine($"6 - 9 - message integrity - [{_sGetArrayAsString(targetData[6..10])}].");

                if (extendedLogs)
                {
                    _sResultBuilder.AppendLine("Message body:");

                    if (targetData[1] == ProtocolMessage.CLIENT_INIT)
                        sGetClientInitBodyTraceMessage(targetData, _sResultBuilder);
                    else if (targetData[1] == ProtocolMessage.SERVER_INIT)
                        sGetServerInitBodyTraceMessage(targetData, _sResultBuilder);
                    else if (targetData[1] == ProtocolMessage.UNSUPPORTED_CLIENT_PARAMS)
                        sGetUnsupportedClientParamsBodyTraceMessage(targetData, _sResultBuilder);
                    else if (targetData[1] == ProtocolMessage.UNSUPPORTED_SERVER_PARAMS)
                        _sResultBuilder.AppendLine();
                    else if (targetData[1] == ProtocolMessage.CLIENT_FINISH)
                        sGetClientFinishBodyTraceMessage(targetData, _sResultBuilder);
                    else if (targetData[1] == ProtocolMessage.DATA_TRANSFER)
                        sGetDataTransferBodyTraceMessage(targetData, _sResultBuilder);
                }

                _sResultBuilder.AppendLine();

                traceAction.Invoke(_sResultBuilder.ToString());
            }
        }

        internal static void sGetClientInitBodyTraceMessage(byte[] targetData, StringBuilder output)
        {
            output.AppendLine($"10 - preferred Cipher Suite - [{targetData[10]}];");

            int publicKeyOffset = 19;
            output.AppendLine($"11 - 18 - supported Cipher Suite - [{_sGetArrayAsString(targetData[11..publicKeyOffset])}];");

            output.AppendLine($"{publicKeyOffset} - {targetData.Length - 1} - KEM public key - [{_sGetArrayAsString(targetData[publicKeyOffset..])}].");
        }

        internal static void sGetServerInitBodyTraceMessage(byte[] targetData, StringBuilder output)
        {
            int cipherTextLength = ProtocolMessage.GetIntValue(targetData, 10, 4);
            output.AppendLine($"10 - 13 - length of the Cipher Text [{cipherTextLength}] - [{_sGetArrayAsString(targetData[10..14])}];");

            byte[] cipherText = new byte[cipherTextLength];
            Array.Copy(targetData, 14, cipherText, 0, cipherTextLength);

            int offset = 14 + cipherTextLength;
            output.AppendLine($"14 - {offset - 1} - Cipher Test - [{_sGetArrayAsString(cipherText)}];");

            int signaturePartLength = ProtocolMessage.GetIntValue(targetData, offset, 4);
            output.AppendLine($"{offset} - {offset + 3} - Signature part length [{signaturePartLength}] - [{_sGetArrayAsString(targetData[offset..(offset+4)])}];");

            offset += 4;
            int signaturePublicKeyLength = ProtocolMessage.GetIntValue(targetData, offset, 4);
            output.AppendLine($"{offset} - {offset + 3} - Signature public key length [{signaturePublicKeyLength}] - [{_sGetArrayAsString(targetData[offset..(offset + 4)])}];");
            
            offset += 4;
            output.AppendLine($"{offset} - {targetData.Length - 1} - Encrypted signature with public key - [{_sGetArrayAsString(targetData[offset..])}].");
        }

        internal static void sGetUnsupportedClientParamsBodyTraceMessage(byte[] targetData, StringBuilder output)
            => output.AppendLine($"10 - 17 - supported Cipher Suites by server - [{_sGetArrayAsString(targetData[10..])}].");
        
        internal static void sGetClientFinishBodyTraceMessage(byte[] targetData, StringBuilder output)
            => output.AppendLine($"10 - {targetData.Length - 1} - encoded hash of the SERVER_INIT message - [{_sGetArrayAsString(targetData[10..])}].");

        internal static void sGetDataTransferBodyTraceMessage(byte[] targetData, StringBuilder output)
            => output.AppendLine($"10 - {targetData.Length - 1} - encrypted message - [{_sGetArrayAsString(targetData[10..])}].");

        private static string _sGetArrayAsString(byte[] data)
        {
            _sPartBuilder.Clear();

            foreach (var el in data)
                _sPartBuilder.Append($"{el} ");

            _sPartBuilder.Remove(_sPartBuilder.Length - 1, 1);
            
            return _sPartBuilder.ToString();
        }
    }
}
