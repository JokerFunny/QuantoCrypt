using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace QuantoCrypt.Infrastructure.Common.Utils
{
    /// <summary>
    /// Utilities to work with packed data.
    /// </summary>
    internal static class Pack
    {
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt32_To_BE(uint n, byte[] bs, int off)
            => BinaryPrimitives.WriteUInt32BigEndian(bs.AsSpan(off), n);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt32_To_BE(uint n, Span<byte> bs)
            => BinaryPrimitives.WriteUInt32BigEndian(bs, n);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt32_To_LE(uint n, Span<byte> bs)
            => BinaryPrimitives.WriteUInt32LittleEndian(bs, n);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt64_To_BE(ulong n, byte[] bs, int off)
            => BinaryPrimitives.WriteUInt64BigEndian(bs.AsSpan(off), n);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt64_To_BE(ulong n, Span<byte> bs)
            => BinaryPrimitives.WriteUInt64BigEndian(bs, n);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt64_To_LE(ulong n, Span<byte> bs)
            => BinaryPrimitives.WriteUInt64LittleEndian(bs, n);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt64_To_LE(ulong[] ns, int nsOff, int nsLen, byte[] bs, int bsOff)
        {
            for (int i = 0; i < nsLen; ++i)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(bs.AsSpan(bsOff), ns[nsOff + i]);

                bsOff += 8;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static void UInt64_To_LE(ReadOnlySpan<ulong> ns, Span<byte> bs)
        {
            for (int i = 0; i < ns.Length; ++i)
            {
                BinaryPrimitives.WriteUInt64LittleEndian(bs, ns[i]);

                bs = bs[8..];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint BE_To_UInt32(byte[] bs, int off)
            => BinaryPrimitives.ReadUInt32BigEndian(bs.AsSpan(off));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint BE_To_UInt32(ReadOnlySpan<byte> bs)
            => BinaryPrimitives.ReadUInt32BigEndian(bs);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong BE_To_UInt64(byte[] bs, int off)
            => BinaryPrimitives.ReadUInt64BigEndian(bs.AsSpan(off));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static ulong BE_To_UInt64(ReadOnlySpan<byte> bs)
            => BinaryPrimitives.ReadUInt64BigEndian(bs);

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint LE_To_UInt32(byte[] bs, int off)
            => BinaryPrimitives.ReadUInt32LittleEndian(bs.AsSpan(off));

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        internal static uint LE_To_UInt32(ReadOnlySpan<byte> bs)
            => BinaryPrimitives.ReadUInt32LittleEndian(bs);
    }
}
