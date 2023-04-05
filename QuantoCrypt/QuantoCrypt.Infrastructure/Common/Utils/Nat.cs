using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace QuantoCrypt.Infrastructure.Common.Utils
{
    internal static class Nat
    {
        public static void XorTo64(int len, ulong[] x, int xOff, ulong[] z, int zOff)
        {
            XorTo64(len, x.AsSpan(xOff, len), z.AsSpan(zOff, len));
        }

        public static void XorTo64(int len, ReadOnlySpan<ulong> x, Span<ulong> z)
        {
            int i = 0, limit8 = len - 8;
            while (i <= limit8)
            {
                Nat512.XorTo64(x[i..], z[i..]);
                i += 8;
            }
            while (i < len)
            {
                z[i] ^= x[i];
                ++i;
            }
        }
    }

    internal static class Nat512
    {
        public static void XorTo64(ReadOnlySpan<ulong> x, Span<ulong> z)
        {
            if (Avx2.IsSupported && Unsafe.SizeOf<Vector256<byte>>() == 32)
            {
                var X = MemoryMarshal.AsBytes(x[..8]);
                var Z = MemoryMarshal.AsBytes(z[..8]);

                var X0 = MemoryMarshal.Read<Vector256<byte>>(X[0x00..0x20]);
                var X1 = MemoryMarshal.Read<Vector256<byte>>(X[0x20..0x40]);

                var Y0 = MemoryMarshal.Read<Vector256<byte>>(Z[0x00..0x20]);
                var Y1 = MemoryMarshal.Read<Vector256<byte>>(Z[0x20..0x40]);

                var Z0 = Avx2.Xor(X0, Y0);
                var Z1 = Avx2.Xor(X1, Y1);

                MemoryMarshal.Write(Z[0x00..0x20], ref Z0);
                MemoryMarshal.Write(Z[0x20..0x40], ref Z1);
                return;
            }

            if (Sse2.IsSupported && Unsafe.SizeOf<Vector128<byte>>() == 16)
            {
                var X = MemoryMarshal.AsBytes(x[..8]);
                var Z = MemoryMarshal.AsBytes(z[..8]);

                var X0 = MemoryMarshal.Read<Vector128<byte>>(X[0x00..0x10]);
                var X1 = MemoryMarshal.Read<Vector128<byte>>(X[0x10..0x20]);
                var X2 = MemoryMarshal.Read<Vector128<byte>>(X[0x20..0x30]);
                var X3 = MemoryMarshal.Read<Vector128<byte>>(X[0x30..0x40]);

                var Y0 = MemoryMarshal.Read<Vector128<byte>>(Z[0x00..0x10]);
                var Y1 = MemoryMarshal.Read<Vector128<byte>>(Z[0x10..0x20]);
                var Y2 = MemoryMarshal.Read<Vector128<byte>>(Z[0x20..0x30]);
                var Y3 = MemoryMarshal.Read<Vector128<byte>>(Z[0x30..0x40]);

                var Z0 = Sse2.Xor(X0, Y0);
                var Z1 = Sse2.Xor(X1, Y1);
                var Z2 = Sse2.Xor(X2, Y2);
                var Z3 = Sse2.Xor(X3, Y3);

                MemoryMarshal.Write(Z[0x00..0x10], ref Z0);
                MemoryMarshal.Write(Z[0x10..0x20], ref Z1);
                MemoryMarshal.Write(Z[0x20..0x30], ref Z2);
                MemoryMarshal.Write(Z[0x30..0x40], ref Z3);
                return;
            }

            for (int i = 0; i < 8; i += 4)
            {
                z[i + 0] ^= x[i + 0];
                z[i + 1] ^= x[i + 1];
                z[i + 2] ^= x[i + 2];
                z[i + 3] ^= x[i + 3];
            }
        }
    }
}
