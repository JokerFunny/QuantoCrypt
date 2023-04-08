``` ini

BenchmarkDotNet=v0.13.5, OS=Windows 11 (10.0.22621.1413/22H2/2022Update/SunValley2)
AMD Ryzen 7 5800X, 1 CPU, 16 logical and 8 physical cores
.NET SDK=7.0.101
  [Host]     : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2
  DefaultJob : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2


```
|                        Method |           name |  dilithiumParameters |      Mean |     Error |    StdDev | Ratio | RatioSD |      Gen0 |     Gen1 | Allocated | Alloc Ratio |
|------------------------------ |--------------- |--------------------- |----------:|----------:|----------:|------:|--------:|----------:|---------:|----------:|------------:|
| **BouncyCastleDilithiumExecutor** |     **dilithium2** | **Org.B(...)eters [66]** |  **7.432 ms** | **0.1459 ms** | **0.1433 ms** |     **?** |       **?** |  **328.1250** |  **39.0625** |   **5.25 MB** |           **?** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
|             **DilithiumExecutor** |     **dilithium2** | **Quant(...)eters [69]** |  **7.049 ms** | **0.1150 ms** | **0.1076 ms** |  **1.00** |    **0.00** |  **328.1250** |  **39.0625** |   **5.31 MB** |        **1.00** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
| **BouncyCastleDilithiumExecutor** | **dilithium2-aes** | **Org.B(...)eters [66]** |  **9.859 ms** | **0.1823 ms** | **0.1705 ms** |     **?** |       **?** |  **437.5000** |  **62.5000** |   **7.05 MB** |           **?** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
|             **DilithiumExecutor** | **dilithium2-aes** | **Quant(...)eters [69]** |  **6.621 ms** | **0.1313 ms** | **0.1797 ms** |  **1.00** |    **0.00** |  **382.8125** |  **54.6875** |   **6.18 MB** |        **1.00** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
| **BouncyCastleDilithiumExecutor** |     **dilithium3** | **Org.B(...)eters [66]** | **12.436 ms** | **0.2437 ms** | **0.3647 ms** |     **?** |       **?** |  **531.2500** | **109.3750** |   **8.63 MB** |           **?** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
|             **DilithiumExecutor** |     **dilithium3** | **Quant(...)eters [69]** | **11.602 ms** | **0.2310 ms** | **0.3386 ms** |  **1.00** |    **0.00** |  **531.2500** | **109.3750** |   **8.61 MB** |        **1.00** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
| **BouncyCastleDilithiumExecutor** | **dilithium3-aes** | **Org.B(...)eters [66]** | **17.587 ms** | **0.3493 ms** | **0.7056 ms** |     **?** |       **?** |  **687.5000** | **125.0000** |  **11.44 MB** |           **?** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
|             **DilithiumExecutor** | **dilithium3-aes** | **Quant(...)eters [69]** | **11.391 ms** | **0.2121 ms** | **0.1880 ms** |  **1.00** |    **0.00** |  **625.0000** | **125.0000** |  **10.15 MB** |        **1.00** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
| **BouncyCastleDilithiumExecutor** |     **dilithium5** | **Org.B(...)eters [66]** | **16.959 ms** | **0.3258 ms** | **0.3346 ms** |     **?** |       **?** |  **718.7500** | **218.7500** |  **11.76 MB** |           **?** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
|             **DilithiumExecutor** |     **dilithium5** | **Quant(...)eters [69]** | **16.396 ms** | **0.3196 ms** | **0.3419 ms** |  **1.00** |    **0.00** |  **718.7500** | **187.5000** |  **11.71 MB** |        **1.00** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
| **BouncyCastleDilithiumExecutor** | **dilithium5-aes** | **Org.B(...)eters [66]** | **26.277 ms** | **0.4575 ms** | **0.4279 ms** |     **?** |       **?** | **1031.2500** | **312.5000** |   **16.8 MB** |           **?** |
|                               |                |                      |           |           |           |       |         |           |          |           |             |
|             **DilithiumExecutor** | **dilithium5-aes** | **Quant(...)eters [69]** | **15.255 ms** | **0.2948 ms** | **0.3936 ms** |  **1.00** |    **0.00** |  **906.2500** | **250.0000** |  **14.78 MB** |        **1.00** |
