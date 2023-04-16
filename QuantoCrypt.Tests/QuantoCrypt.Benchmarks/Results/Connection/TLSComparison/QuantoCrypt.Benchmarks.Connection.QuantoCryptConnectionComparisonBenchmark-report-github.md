``` ini

BenchmarkDotNet=v0.13.5, OS=Windows 11 (10.0.22621.1555/22H2/2022Update/SunValley2)
AMD Ryzen 7 5800X, 1 CPU, 16 logical and 8 physical cores
.NET SDK=7.0.101
  [Host]     : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2
  DefaultJob : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2


```
|                        Method |    name | prefferedCipherSuite |      Mean |     Error |    StdDev | Ratio | RatioSD |     Gen0 |     Gen1 |     Gen2 |  Allocated | Alloc Ratio |
|------------------------------ |-------- |--------------------- |----------:|----------:|----------:|------:|--------:|---------:|---------:|---------:|-----------:|------------:|
|       **TLS12HandshakeDataAsync** |       **?** |                    **?** | **24.772 ms** | **0.0977 ms** | **0.0816 ms** |     **?** |       **?** |        **-** |        **-** |        **-** |   **19.55 KB** |           **?** |
|            TLS12HandshakeData |       ? |                    ? | 24.380 ms | 0.1008 ms | 0.0893 ms |     ? |       ? |        - |        - |        - |   19.44 KB |           ? |
|       TLS13HandshakeDataAsync |       ? |                    ? | 23.779 ms | 0.1715 ms | 0.1432 ms |     ? |       ? |        - |        - |        - |   19.33 KB |           ? |
|            TLS13HandshakeData |       ? |                    ? | 23.808 ms | 0.1177 ms | 0.0983 ms |     ? |       ? |        - |        - |        - |   19.22 KB |           ? |
|                               |         |                      |           |           |           |       |         |          |          |          |            |             |
|      **QuantoCryptHandshakeData** |  **KA_D_A** | **Quant(...)5_Aes [76]** |  **2.320 ms** | **0.0453 ms** | **0.0521 ms** |  **1.00** |    **0.00** | **574.2188** | **546.8750** | **496.0938** | **3352.56 KB** |        **1.00** |
| QuantoCryptHandshakeDataAsync |  KA_D_A | Quant(...)5_Aes [76] |  2.341 ms | 0.0465 ms | 0.0588 ms |  1.01 |    0.04 | 417.9688 | 382.8125 | 339.8438 | 3360.68 KB |        1.00 |
|                               |         |                      |           |           |           |       |         |          |          |          |            |             |
|      **QuantoCryptHandshakeData** | **K_DA_AG** | **Quant(...)esGcm [79]** |  **2.179 ms** | **0.0263 ms** | **0.0246 ms** |  **1.00** |    **0.00** | **585.9375** | **531.2500** | **496.0938** | **3530.13 KB** |        **1.00** |
| QuantoCryptHandshakeDataAsync | K_DA_AG | Quant(...)esGcm [79] |  2.201 ms | 0.0407 ms | 0.0381 ms |  1.01 |    0.03 | 433.5938 | 375.0000 | 347.6563 | 3497.43 KB |        0.99 |
