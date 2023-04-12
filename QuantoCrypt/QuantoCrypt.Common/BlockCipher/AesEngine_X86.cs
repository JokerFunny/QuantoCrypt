using QuantoCrypt.Common.Parameters;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;

namespace QuantoCrypt.Common.BlockCipher
{
    using Aes = System.Runtime.Intrinsics.X86.Aes;
    using Sse2 = System.Runtime.Intrinsics.X86.Sse2;

    /// <summary>
    /// Struct to work with hardware-optimized AES.
    /// </summary>
    public struct AesEngine_X86 : IBlockCipher
    {
        public static bool IsSupported => Aes.IsSupported;

        private enum Mode { DEC_128, DEC_192, DEC_256, ENC_128, ENC_192, ENC_256, UNINITIALIZED };

        private Vector128<byte>[] _roundKeys;
        private Mode _mode = Mode.UNINITIALIZED;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <exception cref="PlatformNotSupportedException">If System.Runtime.Intrinsics.X86.Aes is not supported.</exception>
        public AesEngine_X86()
        {
            if (!IsSupported)
                throw new PlatformNotSupportedException(nameof(AesEngine_X86));
        }

        public string AlgorithmName => "AES";

        public int GetBlockSize() => 16;

        public void Init(bool forEncryption, ICipherParameter parameters)
        {
            if (parameters is not KeyParameter keyParameter)
            {
                ArgumentNullException.ThrowIfNull(parameters, nameof(parameters));
                throw new ArgumentException("invalid type: " + parameters.GetType().FullName, nameof(parameters));
            }

            _roundKeys = _CreateRoundKeys(keyParameter.Key, forEncryption);

            if (_roundKeys.Length == 11)
                _mode = forEncryption ? Mode.ENC_128 : Mode.DEC_128;
            else if (_roundKeys.Length == 13)
                _mode = forEncryption ? Mode.ENC_192 : Mode.DEC_192;
            else
                _mode = forEncryption ? Mode.ENC_256 : Mode.DEC_256;
        }

        public int ProcessBlock(byte[] inBuf, int inOff, byte[] outBuf, int outOff)
        {
            if (inOff > (inBuf.Length - 16))
                throw new ArgumentException("Input buffer too short"); 
            if (outOff > (outBuf.Length - 16))
                throw new ArgumentException("Output buffer too short");

            var state = _Load128(inBuf.AsSpan(inOff, 16));
            _ImplRounds(ref state);
            _Store128(state, outBuf.AsSpan(outOff, 16));
            return 16;
        }

        public int ProcessBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (input.Length < 16)
                throw new ArgumentException("Input buffer too short");
            if (output.Length < 16)
                throw new ArgumentException("Output buffer too short");

            var state = _Load128(input[..16]);
            _ImplRounds(ref state);
            _Store128(state, output[..16]);
            return 16;
        }

        public int ProcessFourBlocks(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (input.Length < 64)
                throw new ArgumentException("Input buffer too short");
            if (output.Length < 64)
                throw new ArgumentException("Output buffer too short");

            var s1 = _Load128(input[..16]);
            var s2 = _Load128(input[16..32]);
            var s3 = _Load128(input[32..48]);
            var s4 = _Load128(input[48..64]);

            _ImplRounds(ref s1, ref s2, ref s3, ref s4);

            _Store128(s1, output[..16]);
            _Store128(s2, output[16..32]);
            _Store128(s3, output[32..48]);
            _Store128(s4, output[48..64]);

            return 64;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void _ImplRounds(ref Vector128<byte> state)
        {
            switch (_mode)
            {
                case Mode.DEC_128: _Decrypt128(_roundKeys, ref state); break;
                case Mode.DEC_192: _Decrypt192(_roundKeys, ref state); break;
                case Mode.DEC_256: _Decrypt256(_roundKeys, ref state); break;
                case Mode.ENC_128: _Encrypt128(_roundKeys, ref state); break;
                case Mode.ENC_192: _Encrypt192(_roundKeys, ref state); break;
                case Mode.ENC_256: _Encrypt256(_roundKeys, ref state); break;
                default: throw new InvalidOperationException(nameof(AesEngine_X86) + " not initialised");
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void _ImplRounds(ref Vector128<byte> s1, ref Vector128<byte> s2, ref Vector128<byte> s3, ref Vector128<byte> s4)
        {
            switch (_mode)
            {
                case Mode.DEC_128: _DecryptFour128(_roundKeys, ref s1, ref s2, ref s3, ref s4); break;
                case Mode.DEC_192: _DecryptFour192(_roundKeys, ref s1, ref s2, ref s3, ref s4); break;
                case Mode.DEC_256: _DecryptFour256(_roundKeys, ref s1, ref s2, ref s3, ref s4); break;
                case Mode.ENC_128: _EncryptFour128(_roundKeys, ref s1, ref s2, ref s3, ref s4); break;
                case Mode.ENC_192: _EncryptFour192(_roundKeys, ref s1, ref s2, ref s3, ref s4); break;
                case Mode.ENC_256: _EncryptFour256(_roundKeys, ref s1, ref s2, ref s3, ref s4); break;
                default: throw new InvalidOperationException(nameof(AesEngine_X86) + " not initialised");
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _Decrypt128(Vector128<byte>[] roundKeys, ref Vector128<byte> state)
        {
            var bounds = roundKeys[10];
            var value = Sse2.Xor(state, roundKeys[0]);
            value = Aes.Decrypt(value, roundKeys[1]);
            value = Aes.Decrypt(value, roundKeys[2]);
            value = Aes.Decrypt(value, roundKeys[3]);
            value = Aes.Decrypt(value, roundKeys[4]);
            value = Aes.Decrypt(value, roundKeys[5]);
            value = Aes.Decrypt(value, roundKeys[6]);
            value = Aes.Decrypt(value, roundKeys[7]);
            value = Aes.Decrypt(value, roundKeys[8]);
            value = Aes.Decrypt(value, roundKeys[9]);
            state = Aes.DecryptLast(value, roundKeys[10]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _Decrypt192(Vector128<byte>[] roundKeys, ref Vector128<byte> state)
        {
            var bounds = roundKeys[12];
            var value = Sse2.Xor(state, roundKeys[0]);
            value = Aes.Decrypt(value, roundKeys[1]);
            value = Aes.Decrypt(value, roundKeys[2]);
            value = Aes.Decrypt(value, roundKeys[3]);
            value = Aes.Decrypt(value, roundKeys[4]);
            value = Aes.Decrypt(value, roundKeys[5]);
            value = Aes.Decrypt(value, roundKeys[6]);
            value = Aes.Decrypt(value, roundKeys[7]);
            value = Aes.Decrypt(value, roundKeys[8]);
            value = Aes.Decrypt(value, roundKeys[9]);
            value = Aes.Decrypt(value, roundKeys[10]);
            value = Aes.Decrypt(value, roundKeys[11]);
            state = Aes.DecryptLast(value, roundKeys[12]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _Decrypt256(Vector128<byte>[] roundKeys, ref Vector128<byte> state)
        {
            var bounds = roundKeys[14];
            var value = Sse2.Xor(state, roundKeys[0]);
            value = Aes.Decrypt(value, roundKeys[1]);
            value = Aes.Decrypt(value, roundKeys[2]);
            value = Aes.Decrypt(value, roundKeys[3]);
            value = Aes.Decrypt(value, roundKeys[4]);
            value = Aes.Decrypt(value, roundKeys[5]);
            value = Aes.Decrypt(value, roundKeys[6]);
            value = Aes.Decrypt(value, roundKeys[7]);
            value = Aes.Decrypt(value, roundKeys[8]);
            value = Aes.Decrypt(value, roundKeys[9]);
            value = Aes.Decrypt(value, roundKeys[10]);
            value = Aes.Decrypt(value, roundKeys[11]);
            value = Aes.Decrypt(value, roundKeys[12]);
            value = Aes.Decrypt(value, roundKeys[13]);
            state = Aes.DecryptLast(value, roundKeys[14]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _DecryptFour128(Vector128<byte>[] rk, ref Vector128<byte> s1, ref Vector128<byte> s2, 
            ref Vector128<byte> s3, ref Vector128<byte> s4)
        {
            var bounds = rk[10];

            var v1 = Sse2.Xor(s1, rk[0]);
            var v2 = Sse2.Xor(s2, rk[0]);
            var v3 = Sse2.Xor(s3, rk[0]);
            var v4 = Sse2.Xor(s4, rk[0]);

            v1 = Aes.Decrypt(v1, rk[1]);
            v2 = Aes.Decrypt(v2, rk[1]);
            v3 = Aes.Decrypt(v3, rk[1]);
            v4 = Aes.Decrypt(v4, rk[1]);

            v1 = Aes.Decrypt(v1, rk[2]);
            v2 = Aes.Decrypt(v2, rk[2]);
            v3 = Aes.Decrypt(v3, rk[2]);
            v4 = Aes.Decrypt(v4, rk[2]);

            v1 = Aes.Decrypt(v1, rk[3]);
            v2 = Aes.Decrypt(v2, rk[3]);
            v3 = Aes.Decrypt(v3, rk[3]);
            v4 = Aes.Decrypt(v4, rk[3]);

            v1 = Aes.Decrypt(v1, rk[4]);
            v2 = Aes.Decrypt(v2, rk[4]);
            v3 = Aes.Decrypt(v3, rk[4]);
            v4 = Aes.Decrypt(v4, rk[4]);

            v1 = Aes.Decrypt(v1, rk[5]);
            v2 = Aes.Decrypt(v2, rk[5]);
            v3 = Aes.Decrypt(v3, rk[5]);
            v4 = Aes.Decrypt(v4, rk[5]);

            v1 = Aes.Decrypt(v1, rk[6]);
            v2 = Aes.Decrypt(v2, rk[6]);
            v3 = Aes.Decrypt(v3, rk[6]);
            v4 = Aes.Decrypt(v4, rk[6]);

            v1 = Aes.Decrypt(v1, rk[7]);
            v2 = Aes.Decrypt(v2, rk[7]);
            v3 = Aes.Decrypt(v3, rk[7]);
            v4 = Aes.Decrypt(v4, rk[7]);

            v1 = Aes.Decrypt(v1, rk[8]);
            v2 = Aes.Decrypt(v2, rk[8]);
            v3 = Aes.Decrypt(v3, rk[8]);
            v4 = Aes.Decrypt(v4, rk[8]);

            v1 = Aes.Decrypt(v1, rk[9]);
            v2 = Aes.Decrypt(v2, rk[9]);
            v3 = Aes.Decrypt(v3, rk[9]);
            v4 = Aes.Decrypt(v4, rk[9]);

            s1 = Aes.DecryptLast(v1, rk[10]);
            s2 = Aes.DecryptLast(v2, rk[10]);
            s3 = Aes.DecryptLast(v3, rk[10]);
            s4 = Aes.DecryptLast(v4, rk[10]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _DecryptFour192(Vector128<byte>[] rk, ref Vector128<byte> s1, ref Vector128<byte> s2, 
            ref Vector128<byte> s3, ref Vector128<byte> s4)
        {
            var bounds = rk[12];

            var v1 = Sse2.Xor(s1, rk[0]);
            var v2 = Sse2.Xor(s2, rk[0]);
            var v3 = Sse2.Xor(s3, rk[0]);
            var v4 = Sse2.Xor(s4, rk[0]);

            v1 = Aes.Decrypt(v1, rk[1]);
            v2 = Aes.Decrypt(v2, rk[1]);
            v3 = Aes.Decrypt(v3, rk[1]);
            v4 = Aes.Decrypt(v4, rk[1]);

            v1 = Aes.Decrypt(v1, rk[2]);
            v2 = Aes.Decrypt(v2, rk[2]);
            v3 = Aes.Decrypt(v3, rk[2]);
            v4 = Aes.Decrypt(v4, rk[2]);

            v1 = Aes.Decrypt(v1, rk[3]);
            v2 = Aes.Decrypt(v2, rk[3]);
            v3 = Aes.Decrypt(v3, rk[3]);
            v4 = Aes.Decrypt(v4, rk[3]);

            v1 = Aes.Decrypt(v1, rk[4]);
            v2 = Aes.Decrypt(v2, rk[4]);
            v3 = Aes.Decrypt(v3, rk[4]);
            v4 = Aes.Decrypt(v4, rk[4]);

            v1 = Aes.Decrypt(v1, rk[5]);
            v2 = Aes.Decrypt(v2, rk[5]);
            v3 = Aes.Decrypt(v3, rk[5]);
            v4 = Aes.Decrypt(v4, rk[5]);

            v1 = Aes.Decrypt(v1, rk[6]);
            v2 = Aes.Decrypt(v2, rk[6]);
            v3 = Aes.Decrypt(v3, rk[6]);
            v4 = Aes.Decrypt(v4, rk[6]);

            v1 = Aes.Decrypt(v1, rk[7]);
            v2 = Aes.Decrypt(v2, rk[7]);
            v3 = Aes.Decrypt(v3, rk[7]);
            v4 = Aes.Decrypt(v4, rk[7]);

            v1 = Aes.Decrypt(v1, rk[8]);
            v2 = Aes.Decrypt(v2, rk[8]);
            v3 = Aes.Decrypt(v3, rk[8]);
            v4 = Aes.Decrypt(v4, rk[8]);

            v1 = Aes.Decrypt(v1, rk[9]);
            v2 = Aes.Decrypt(v2, rk[9]);
            v3 = Aes.Decrypt(v3, rk[9]);
            v4 = Aes.Decrypt(v4, rk[9]);

            v1 = Aes.Decrypt(v1, rk[10]);
            v2 = Aes.Decrypt(v2, rk[10]);
            v3 = Aes.Decrypt(v3, rk[10]);
            v4 = Aes.Decrypt(v4, rk[10]);

            v1 = Aes.Decrypt(v1, rk[11]);
            v2 = Aes.Decrypt(v2, rk[11]);
            v3 = Aes.Decrypt(v3, rk[11]);
            v4 = Aes.Decrypt(v4, rk[11]);

            s1 = Aes.DecryptLast(v1, rk[12]);
            s2 = Aes.DecryptLast(v2, rk[12]);
            s3 = Aes.DecryptLast(v3, rk[12]);
            s4 = Aes.DecryptLast(v4, rk[12]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _DecryptFour256(Vector128<byte>[] rk, ref Vector128<byte> s1, ref Vector128<byte> s2, 
            ref Vector128<byte> s3, ref Vector128<byte> s4)
        {
            var bounds = rk[14];

            var v1 = Sse2.Xor(s1, rk[0]);
            var v2 = Sse2.Xor(s2, rk[0]);
            var v3 = Sse2.Xor(s3, rk[0]);
            var v4 = Sse2.Xor(s4, rk[0]);

            v1 = Aes.Decrypt(v1, rk[1]);
            v2 = Aes.Decrypt(v2, rk[1]);
            v3 = Aes.Decrypt(v3, rk[1]);
            v4 = Aes.Decrypt(v4, rk[1]);

            v1 = Aes.Decrypt(v1, rk[2]);
            v2 = Aes.Decrypt(v2, rk[2]);
            v3 = Aes.Decrypt(v3, rk[2]);
            v4 = Aes.Decrypt(v4, rk[2]);

            v1 = Aes.Decrypt(v1, rk[3]);
            v2 = Aes.Decrypt(v2, rk[3]);
            v3 = Aes.Decrypt(v3, rk[3]);
            v4 = Aes.Decrypt(v4, rk[3]);

            v1 = Aes.Decrypt(v1, rk[4]);
            v2 = Aes.Decrypt(v2, rk[4]);
            v3 = Aes.Decrypt(v3, rk[4]);
            v4 = Aes.Decrypt(v4, rk[4]);

            v1 = Aes.Decrypt(v1, rk[5]);
            v2 = Aes.Decrypt(v2, rk[5]);
            v3 = Aes.Decrypt(v3, rk[5]);
            v4 = Aes.Decrypt(v4, rk[5]);

            v1 = Aes.Decrypt(v1, rk[6]);
            v2 = Aes.Decrypt(v2, rk[6]);
            v3 = Aes.Decrypt(v3, rk[6]);
            v4 = Aes.Decrypt(v4, rk[6]);

            v1 = Aes.Decrypt(v1, rk[7]);
            v2 = Aes.Decrypt(v2, rk[7]);
            v3 = Aes.Decrypt(v3, rk[7]);
            v4 = Aes.Decrypt(v4, rk[7]);

            v1 = Aes.Decrypt(v1, rk[8]);
            v2 = Aes.Decrypt(v2, rk[8]);
            v3 = Aes.Decrypt(v3, rk[8]);
            v4 = Aes.Decrypt(v4, rk[8]);

            v1 = Aes.Decrypt(v1, rk[9]);
            v2 = Aes.Decrypt(v2, rk[9]);
            v3 = Aes.Decrypt(v3, rk[9]);
            v4 = Aes.Decrypt(v4, rk[9]);

            v1 = Aes.Decrypt(v1, rk[10]);
            v2 = Aes.Decrypt(v2, rk[10]);
            v3 = Aes.Decrypt(v3, rk[10]);
            v4 = Aes.Decrypt(v4, rk[10]);

            v1 = Aes.Decrypt(v1, rk[11]);
            v2 = Aes.Decrypt(v2, rk[11]);
            v3 = Aes.Decrypt(v3, rk[11]);
            v4 = Aes.Decrypt(v4, rk[11]);

            v1 = Aes.Decrypt(v1, rk[12]);
            v2 = Aes.Decrypt(v2, rk[12]);
            v3 = Aes.Decrypt(v3, rk[12]);
            v4 = Aes.Decrypt(v4, rk[12]);

            v1 = Aes.Decrypt(v1, rk[13]);
            v2 = Aes.Decrypt(v2, rk[13]);
            v3 = Aes.Decrypt(v3, rk[13]);
            v4 = Aes.Decrypt(v4, rk[13]);

            s1 = Aes.DecryptLast(v1, rk[14]);
            s2 = Aes.DecryptLast(v2, rk[14]);
            s3 = Aes.DecryptLast(v3, rk[14]);
            s4 = Aes.DecryptLast(v4, rk[14]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _Encrypt128(Vector128<byte>[] roundKeys, ref Vector128<byte> state)
        {
            var bounds = roundKeys[10];
            var value = Sse2.Xor(state, roundKeys[0]);
            value = Aes.Encrypt(value, roundKeys[1]);
            value = Aes.Encrypt(value, roundKeys[2]);
            value = Aes.Encrypt(value, roundKeys[3]);
            value = Aes.Encrypt(value, roundKeys[4]);
            value = Aes.Encrypt(value, roundKeys[5]);
            value = Aes.Encrypt(value, roundKeys[6]);
            value = Aes.Encrypt(value, roundKeys[7]);
            value = Aes.Encrypt(value, roundKeys[8]);
            value = Aes.Encrypt(value, roundKeys[9]);
            state = Aes.EncryptLast(value, roundKeys[10]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _Encrypt192(Vector128<byte>[] roundKeys, ref Vector128<byte> state)
        {
            var bounds = roundKeys[12];
            var value = Sse2.Xor(state, roundKeys[0]);
            value = Aes.Encrypt(value, roundKeys[1]);
            value = Aes.Encrypt(value, roundKeys[2]);
            value = Aes.Encrypt(value, roundKeys[3]);
            value = Aes.Encrypt(value, roundKeys[4]);
            value = Aes.Encrypt(value, roundKeys[5]);
            value = Aes.Encrypt(value, roundKeys[6]);
            value = Aes.Encrypt(value, roundKeys[7]);
            value = Aes.Encrypt(value, roundKeys[8]);
            value = Aes.Encrypt(value, roundKeys[9]);
            value = Aes.Encrypt(value, roundKeys[10]);
            value = Aes.Encrypt(value, roundKeys[11]);
            state = Aes.EncryptLast(value, roundKeys[12]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _Encrypt256(Vector128<byte>[] roundKeys, ref Vector128<byte> state)
        {
            var bounds = roundKeys[14];
            var value = Sse2.Xor(state, roundKeys[0]);
            value = Aes.Encrypt(value, roundKeys[1]);
            value = Aes.Encrypt(value, roundKeys[2]);
            value = Aes.Encrypt(value, roundKeys[3]);
            value = Aes.Encrypt(value, roundKeys[4]);
            value = Aes.Encrypt(value, roundKeys[5]);
            value = Aes.Encrypt(value, roundKeys[6]);
            value = Aes.Encrypt(value, roundKeys[7]);
            value = Aes.Encrypt(value, roundKeys[8]);
            value = Aes.Encrypt(value, roundKeys[9]);
            value = Aes.Encrypt(value, roundKeys[10]);
            value = Aes.Encrypt(value, roundKeys[11]);
            value = Aes.Encrypt(value, roundKeys[12]);
            value = Aes.Encrypt(value, roundKeys[13]);
            state = Aes.EncryptLast(value, roundKeys[14]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _EncryptFour128(Vector128<byte>[] rk, ref Vector128<byte> s1, ref Vector128<byte> s2, 
            ref Vector128<byte> s3, ref Vector128<byte> s4)
        {
            var bounds = rk[10];

            var v1 = Sse2.Xor(s1, rk[0]);
            var v2 = Sse2.Xor(s2, rk[0]);
            var v3 = Sse2.Xor(s3, rk[0]);
            var v4 = Sse2.Xor(s4, rk[0]);

            v1 = Aes.Encrypt(v1, rk[1]);
            v2 = Aes.Encrypt(v2, rk[1]);
            v3 = Aes.Encrypt(v3, rk[1]);
            v4 = Aes.Encrypt(v4, rk[1]);

            v1 = Aes.Encrypt(v1, rk[2]);
            v2 = Aes.Encrypt(v2, rk[2]);
            v3 = Aes.Encrypt(v3, rk[2]);
            v4 = Aes.Encrypt(v4, rk[2]);

            v1 = Aes.Encrypt(v1, rk[3]);
            v2 = Aes.Encrypt(v2, rk[3]);
            v3 = Aes.Encrypt(v3, rk[3]);
            v4 = Aes.Encrypt(v4, rk[3]);

            v1 = Aes.Encrypt(v1, rk[4]);
            v2 = Aes.Encrypt(v2, rk[4]);
            v3 = Aes.Encrypt(v3, rk[4]);
            v4 = Aes.Encrypt(v4, rk[4]);

            v1 = Aes.Encrypt(v1, rk[5]);
            v2 = Aes.Encrypt(v2, rk[5]);
            v3 = Aes.Encrypt(v3, rk[5]);
            v4 = Aes.Encrypt(v4, rk[5]);

            v1 = Aes.Encrypt(v1, rk[6]);
            v2 = Aes.Encrypt(v2, rk[6]);
            v3 = Aes.Encrypt(v3, rk[6]);
            v4 = Aes.Encrypt(v4, rk[6]);

            v1 = Aes.Encrypt(v1, rk[7]);
            v2 = Aes.Encrypt(v2, rk[7]);
            v3 = Aes.Encrypt(v3, rk[7]);
            v4 = Aes.Encrypt(v4, rk[7]);

            v1 = Aes.Encrypt(v1, rk[8]);
            v2 = Aes.Encrypt(v2, rk[8]);
            v3 = Aes.Encrypt(v3, rk[8]);
            v4 = Aes.Encrypt(v4, rk[8]);

            v1 = Aes.Encrypt(v1, rk[9]);
            v2 = Aes.Encrypt(v2, rk[9]);
            v3 = Aes.Encrypt(v3, rk[9]);
            v4 = Aes.Encrypt(v4, rk[9]);

            s1 = Aes.EncryptLast(v1, rk[10]);
            s2 = Aes.EncryptLast(v2, rk[10]);
            s3 = Aes.EncryptLast(v3, rk[10]);
            s4 = Aes.EncryptLast(v4, rk[10]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _EncryptFour192(Vector128<byte>[] rk, ref Vector128<byte> s1, ref Vector128<byte> s2, 
            ref Vector128<byte> s3, ref Vector128<byte> s4)
        {
            var bounds = rk[12];

            var v1 = Sse2.Xor(s1, rk[0]);
            var v2 = Sse2.Xor(s2, rk[0]);
            var v3 = Sse2.Xor(s3, rk[0]);
            var v4 = Sse2.Xor(s4, rk[0]);

            v1 = Aes.Encrypt(v1, rk[1]);
            v2 = Aes.Encrypt(v2, rk[1]);
            v3 = Aes.Encrypt(v3, rk[1]);
            v4 = Aes.Encrypt(v4, rk[1]);

            v1 = Aes.Encrypt(v1, rk[2]);
            v2 = Aes.Encrypt(v2, rk[2]);
            v3 = Aes.Encrypt(v3, rk[2]);
            v4 = Aes.Encrypt(v4, rk[2]);

            v1 = Aes.Encrypt(v1, rk[3]);
            v2 = Aes.Encrypt(v2, rk[3]);
            v3 = Aes.Encrypt(v3, rk[3]);
            v4 = Aes.Encrypt(v4, rk[3]);

            v1 = Aes.Encrypt(v1, rk[4]);
            v2 = Aes.Encrypt(v2, rk[4]);
            v3 = Aes.Encrypt(v3, rk[4]);
            v4 = Aes.Encrypt(v4, rk[4]);

            v1 = Aes.Encrypt(v1, rk[5]);
            v2 = Aes.Encrypt(v2, rk[5]);
            v3 = Aes.Encrypt(v3, rk[5]);
            v4 = Aes.Encrypt(v4, rk[5]);

            v1 = Aes.Encrypt(v1, rk[6]);
            v2 = Aes.Encrypt(v2, rk[6]);
            v3 = Aes.Encrypt(v3, rk[6]);
            v4 = Aes.Encrypt(v4, rk[6]);

            v1 = Aes.Encrypt(v1, rk[7]);
            v2 = Aes.Encrypt(v2, rk[7]);
            v3 = Aes.Encrypt(v3, rk[7]);
            v4 = Aes.Encrypt(v4, rk[7]);

            v1 = Aes.Encrypt(v1, rk[8]);
            v2 = Aes.Encrypt(v2, rk[8]);
            v3 = Aes.Encrypt(v3, rk[8]);
            v4 = Aes.Encrypt(v4, rk[8]);

            v1 = Aes.Encrypt(v1, rk[9]);
            v2 = Aes.Encrypt(v2, rk[9]);
            v3 = Aes.Encrypt(v3, rk[9]);
            v4 = Aes.Encrypt(v4, rk[9]);

            v1 = Aes.Encrypt(v1, rk[10]);
            v2 = Aes.Encrypt(v2, rk[10]);
            v3 = Aes.Encrypt(v3, rk[10]);
            v4 = Aes.Encrypt(v4, rk[10]);

            v1 = Aes.Encrypt(v1, rk[11]);
            v2 = Aes.Encrypt(v2, rk[11]);
            v3 = Aes.Encrypt(v3, rk[11]);
            v4 = Aes.Encrypt(v4, rk[11]);

            s1 = Aes.EncryptLast(v1, rk[12]);
            s2 = Aes.EncryptLast(v2, rk[12]);
            s3 = Aes.EncryptLast(v3, rk[12]);
            s4 = Aes.EncryptLast(v4, rk[12]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _EncryptFour256(Vector128<byte>[] rk, ref Vector128<byte> s1, ref Vector128<byte> s2, 
            ref Vector128<byte> s3, ref Vector128<byte> s4)
        {
            var bounds = rk[14];

            var v1 = Sse2.Xor(s1, rk[0]);
            var v2 = Sse2.Xor(s2, rk[0]);
            var v3 = Sse2.Xor(s3, rk[0]);
            var v4 = Sse2.Xor(s4, rk[0]);

            v1 = Aes.Encrypt(v1, rk[1]);
            v2 = Aes.Encrypt(v2, rk[1]);
            v3 = Aes.Encrypt(v3, rk[1]);
            v4 = Aes.Encrypt(v4, rk[1]);

            v1 = Aes.Encrypt(v1, rk[2]);
            v2 = Aes.Encrypt(v2, rk[2]);
            v3 = Aes.Encrypt(v3, rk[2]);
            v4 = Aes.Encrypt(v4, rk[2]);

            v1 = Aes.Encrypt(v1, rk[3]);
            v2 = Aes.Encrypt(v2, rk[3]);
            v3 = Aes.Encrypt(v3, rk[3]);
            v4 = Aes.Encrypt(v4, rk[3]);

            v1 = Aes.Encrypt(v1, rk[4]);
            v2 = Aes.Encrypt(v2, rk[4]);
            v3 = Aes.Encrypt(v3, rk[4]);
            v4 = Aes.Encrypt(v4, rk[4]);

            v1 = Aes.Encrypt(v1, rk[5]);
            v2 = Aes.Encrypt(v2, rk[5]);
            v3 = Aes.Encrypt(v3, rk[5]);
            v4 = Aes.Encrypt(v4, rk[5]);

            v1 = Aes.Encrypt(v1, rk[6]);
            v2 = Aes.Encrypt(v2, rk[6]);
            v3 = Aes.Encrypt(v3, rk[6]);
            v4 = Aes.Encrypt(v4, rk[6]);

            v1 = Aes.Encrypt(v1, rk[7]);
            v2 = Aes.Encrypt(v2, rk[7]);
            v3 = Aes.Encrypt(v3, rk[7]);
            v4 = Aes.Encrypt(v4, rk[7]);

            v1 = Aes.Encrypt(v1, rk[8]);
            v2 = Aes.Encrypt(v2, rk[8]);
            v3 = Aes.Encrypt(v3, rk[8]);
            v4 = Aes.Encrypt(v4, rk[8]);

            v1 = Aes.Encrypt(v1, rk[9]);
            v2 = Aes.Encrypt(v2, rk[9]);
            v3 = Aes.Encrypt(v3, rk[9]);
            v4 = Aes.Encrypt(v4, rk[9]);

            v1 = Aes.Encrypt(v1, rk[10]);
            v2 = Aes.Encrypt(v2, rk[10]);
            v3 = Aes.Encrypt(v3, rk[10]);
            v4 = Aes.Encrypt(v4, rk[10]);

            v1 = Aes.Encrypt(v1, rk[11]);
            v2 = Aes.Encrypt(v2, rk[11]);
            v3 = Aes.Encrypt(v3, rk[11]);
            v4 = Aes.Encrypt(v4, rk[11]);

            v1 = Aes.Encrypt(v1, rk[12]);
            v2 = Aes.Encrypt(v2, rk[12]);
            v3 = Aes.Encrypt(v3, rk[12]);
            v4 = Aes.Encrypt(v4, rk[12]);

            v1 = Aes.Encrypt(v1, rk[13]);
            v2 = Aes.Encrypt(v2, rk[13]);
            v3 = Aes.Encrypt(v3, rk[13]);
            v4 = Aes.Encrypt(v4, rk[13]);

            s1 = Aes.EncryptLast(v1, rk[14]);
            s2 = Aes.EncryptLast(v2, rk[14]);
            s3 = Aes.EncryptLast(v3, rk[14]);
            s4 = Aes.EncryptLast(v4, rk[14]);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector128<byte> _Load128(ReadOnlySpan<byte> t)
        {
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<byte>>() == 16)
                return MemoryMarshal.Read<Vector128<byte>>(t);

            return Vector128.Create(
                BinaryPrimitives.ReadUInt64LittleEndian(t[..8]),
                BinaryPrimitives.ReadUInt64LittleEndian(t[8..])
            ).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static Vector64<byte> _Load64(ReadOnlySpan<byte> t)
        {
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector64<byte>>() == 8)
                return MemoryMarshal.Read<Vector64<byte>>(t);

            return Vector64.Create(
                BinaryPrimitives.ReadUInt64LittleEndian(t[..8])
            ).AsByte();
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private static void _Store128(Vector128<byte> s, Span<byte> t)
        {
            if (BitConverter.IsLittleEndian && Unsafe.SizeOf<Vector128<byte>>() == 16)
            {
                MemoryMarshal.Write(t, ref s);
                return;
            }

            var u = s.AsUInt64();
            BinaryPrimitives.WriteUInt64LittleEndian(t[..8], u.GetElement(0));
            BinaryPrimitives.WriteUInt64LittleEndian(t[8..], u.GetElement(1));
        }


        private static Vector128<byte>[] _CreateRoundKeys(ReadOnlySpan<byte> key, bool forEncryption)
        {
            Vector128<byte>[] K;

            switch (key.Length)
            {
                case 16:
                    {
                        ReadOnlySpan<byte> rcon = stackalloc byte[] { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

                        K = new Vector128<byte>[11];

                        var s = _Load128(key[..16]);
                        K[0] = s;

                        for (int round = 0; round < 10;)
                        {
                            var t = Aes.KeygenAssist(s, rcon[round++]);
                            t = Sse2.Shuffle(t.AsInt32(), 0xFF).AsByte();
                            s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 8));
                            s = Sse2.Xor(s, Sse2.ShiftLeftLogical128BitLane(s, 4));
                            s = Sse2.Xor(s, t);
                            K[round] = s;
                        }

                        break;
                    }
                case 24:
                    {
                        K = new Vector128<byte>[13];

                        var s1 = _Load128(key[..16]);
                        var s2 = _Load64(key[16..24]).ToVector128();
                        K[0] = s1;

                        byte rcon = 0x01;
                        for (int round = 0; ;)
                        {
                            var t1 = Aes.KeygenAssist(s2, rcon); rcon <<= 1;
                            t1 = Sse2.Shuffle(t1.AsInt32(), 0x55).AsByte();

                            s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 8));
                            s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 4));
                            s1 = Sse2.Xor(s1, t1);

                            K[++round] = Sse2.Xor(s2, Sse2.ShiftLeftLogical128BitLane(s1, 8));

                            var s3 = Sse2.Xor(s2, Sse2.ShiftRightLogical128BitLane(s1, 12));
                            s3 = Sse2.Xor(s3, Sse2.ShiftLeftLogical128BitLane(s3, 4));

                            K[++round] = Sse2.Xor(
                                Sse2.ShiftRightLogical128BitLane(s1, 8),
                                Sse2.ShiftLeftLogical128BitLane(s3, 8));

                            var t2 = Aes.KeygenAssist(s3, rcon); rcon <<= 1;
                            t2 = Sse2.Shuffle(t2.AsInt32(), 0x55).AsByte();

                            s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 8));
                            s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 4));
                            s1 = Sse2.Xor(s1, t2);

                            K[++round] = s1;

                            if (round == 12)
                                break;

                            s2 = Sse2.Xor(s3, Sse2.ShiftRightLogical128BitLane(s1, 12));
                            s2 = Sse2.Xor(s2, Sse2.ShiftLeftLogical128BitLane(s2, 4));
                            s2 = s2.WithUpper(Vector64<byte>.Zero);
                        }

                        break;
                    }
                case 32:
                    {
                        K = new Vector128<byte>[15];

                        var s1 = _Load128(key[..16]);
                        var s2 = _Load128(key[16..32]);
                        K[0] = s1;
                        K[1] = s2;

                        byte rcon = 0x01;
                        for (int round = 1; ;)
                        {
                            var t1 = Aes.KeygenAssist(s2, rcon); rcon <<= 1;
                            t1 = Sse2.Shuffle(t1.AsInt32(), 0xFF).AsByte();
                            s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 8));
                            s1 = Sse2.Xor(s1, Sse2.ShiftLeftLogical128BitLane(s1, 4));
                            s1 = Sse2.Xor(s1, t1);
                            K[++round] = s1;

                            if (round == 14)
                                break;

                            var t2 = Aes.KeygenAssist(s1, 0x00);
                            t2 = Sse2.Shuffle(t2.AsInt32(), 0xAA).AsByte();
                            s2 = Sse2.Xor(s2, Sse2.ShiftLeftLogical128BitLane(s2, 8));
                            s2 = Sse2.Xor(s2, Sse2.ShiftLeftLogical128BitLane(s2, 4));
                            s2 = Sse2.Xor(s2, t2);
                            K[++round] = s2;
                        }

                        break;
                    }
                default:
                    throw new ArgumentException("Key length not 128/192/256 bits.");
            }

            if (!forEncryption)
            {
                for (int i = 1, last = K.Length - 1; i < last; ++i)
                    K[i] = Aes.InverseMixColumns(K[i]);

                Array.Reverse(K);
            }

            return K;
        }

    }
}
