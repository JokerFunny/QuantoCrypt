using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Jobs;

namespace QuantoCrypt.Benchmarks.Configuration
{
    /// <summary>
    /// Fast config to check something in a fast way.
    /// </summary>
    public class FastAndDirtyConfig : ManualConfig
    {
        public FastAndDirtyConfig()
        {
            Add(DefaultConfig.Instance);

            AddJob(Job.Default
                .WithLaunchCount(1)     // benchmark process will be launched only once
                .WithIterationTime(new Perfolizer.Horology.TimeInterval(100, Perfolizer.Horology.TimeUnit.Millisecond)) // 100ms per iteration
                .WithWarmupCount(2)     // 2 warmup iteration
                .WithIterationCount(3)     // 3 target iteration
            );
        }
    }
}
