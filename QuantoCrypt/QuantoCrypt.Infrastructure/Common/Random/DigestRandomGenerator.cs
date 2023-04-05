using QuantoCrypt.Infrastructure.Common.Digest;
using QuantoCrypt.Infrastructure.Common.Utils;

namespace QuantoCrypt.Infrastructure.Common.Random
{
    /// <summary>
    /// Random generation based on the _rDigest with counter. Calling AddSeedMaterial will always increase the entropy of the hash.
    /// </summary>
    public sealed class DigestRandomGenerator : IRandomGenerator
    {
        private const long CYCLE_COUNT = 10;

        private readonly IDigest _rDigest;
        private readonly byte[] _rState;
        private readonly byte[] _rSeed;

        private long _stateCounter;
        private long _seedCounter;

        /// <summary>
        /// Default ctor.
        /// </summary>
        /// <param name="digest">Target <see cref="IDigest"/>.</param>
        public DigestRandomGenerator(IDigest digest)
        {
            _rDigest = digest;

            _rSeed = new byte[digest.GetDigestSize()];
            _seedCounter = 1;

            _rState = new byte[digest.GetDigestSize()];
            _stateCounter = 1;
        }

        public void AddSeedMaterial(byte[] inSeed)
        {
            lock (this)
            {
                if (!(inSeed == null || inSeed.Length < 1))
                    _DigestUpdate(inSeed);

                _DigestUpdate(_rSeed);
                _DigestDoFinal(_rSeed);
            }
        }

        public void AddSeedMaterial(ReadOnlySpan<byte> inSeed)
        {
            lock (this)
            {
                if (!inSeed.IsEmpty)
                    _DigestUpdate(inSeed);

                _DigestUpdate(_rSeed);
                _DigestDoFinal(_rSeed);
            }
        }

        public void AddSeedMaterial(long rSeed)
        {
            lock (this)
            {
                _DigestAddCounter(rSeed);
                _DigestUpdate(_rSeed);
                _DigestDoFinal(_rSeed);
            }
        }

        public void NextBytes(byte[] bytes)
            => NextBytes(bytes, 0, bytes.Length);

        public void NextBytes(byte[] bytes, int start, int len)
            => NextBytes(bytes.AsSpan(start, len));

        public void NextBytes(Span<byte> bytes)
        {
            lock (this)
            {
                int stateOff = 0;

                _GenerateState();

                for (int i = 0; i < bytes.Length; ++i)
                {
                    if (stateOff == _rState.Length)
                    {
                        _GenerateState();
                        stateOff = 0;
                    }

                    bytes[i] = _rState[stateOff++];
                }
            }
        }

        private void _CycleSeed()
        {
            _DigestUpdate(_rSeed);
            _DigestAddCounter(_seedCounter++);
            _DigestDoFinal(_rSeed);
        }

        private void _GenerateState()
        {
            _DigestAddCounter(_stateCounter++);
            _DigestUpdate(_rState);
            _DigestUpdate(_rSeed);
            _DigestDoFinal(_rState);

            if ((_stateCounter % CYCLE_COUNT) == 0)
                _CycleSeed();
        }

        private void _DigestAddCounter(long seedVal)
        {
            Span<byte> bytes = stackalloc byte[8];
            Pack.UInt64_To_LE((ulong)seedVal, bytes);
            _rDigest.BlockUpdate(bytes);
        }

        private void _DigestUpdate(ReadOnlySpan<byte> inSeed)
            => _rDigest.BlockUpdate(inSeed);

        private void _DigestDoFinal(Span<byte> result)
            => _rDigest.DoFinal(result);
    }
}
