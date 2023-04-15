``` ini

BenchmarkDotNet=v0.13.5, OS=Windows 11 (10.0.22621.1555/22H2/2022Update/SunValley2)
AMD Ryzen 7 5800X, 1 CPU, 16 logical and 8 physical cores
.NET SDK=7.0.101
  [Host]     : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2
  Job-ZSFQKN : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2

IterationTime=100.0000 ms  LaunchCount=1  

```
|                                             Method | targetAes | prefferedCipherSuite |       Mean |      Error |      StdDev |     Median |  Ratio | RatioSD |      Gen0 |      Gen1 |      Gen2 |  Allocated | Alloc Ratio |
|--------------------------------------------------- |---------- |--------------------- |-----------:|-----------:|------------:|-----------:|-------:|--------:|----------:|----------:|----------:|-----------:|------------:|
|           **DefaulConnectionModeWithDataTransfer1024** |       **AES** | **Quant(...)s_Aes [76]** |   **2.092 ms** |  **0.0513 ms** |   **0.1504 ms** |   **2.093 ms** |   **1.00** |    **0.00** |   **76.9231** |         **-** |         **-** |    **4.35 MB** |        **1.00** |
|      DefaulConnectionModeWithDataTransferAsync1024 |       AES | Quant(...)s_Aes [76] |   2.046 ms |  0.0612 ms |   0.1787 ms |   2.009 ms |   0.98 |    0.11 |   62.5000 |         - |         - |    4.47 MB |        1.03 |
|        DefaulConnectionModeWithDataTransfer1048576 |       AES | Quant(...)s_Aes [76] |  10.386 ms |  0.2060 ms |   0.4650 ms |  10.365 ms |   5.06 |    0.43 |         - |         - |         - |   18.44 MB |        4.23 |
|   DefaulConnectionModeWithDataTransferAsync1048576 |       AES | Quant(...)s_Aes [76] |  10.373 ms |  0.2052 ms |   0.5405 ms |  10.383 ms |   4.96 |    0.47 |         - |         - |         - |   17.49 MB |        4.02 |
|      DefaulConnectionModeWithDataTransfer104857600 |       AES | Quant(...)s_Aes [76] | 617.358 ms | 33.9465 ms | 100.0921 ms | 648.165 ms | 296.42 |   53.02 | 2000.0000 | 2000.0000 | 2000.0000 | 1359.36 MB |      312.19 |
| DefaulConnectionModeWithDataTransferAsync104857600 |       AES | Quant(...)s_Aes [76] | 588.745 ms | 26.9411 ms |  76.8644 ms | 602.852 ms | 282.63 |   43.40 | 2000.0000 | 2000.0000 | 2000.0000 | 1359.29 MB |      312.17 |
|                                                    |           |                      |            |            |             |            |        |         |           |           |           |            |             |
|           **DefaulConnectionModeWithDataTransfer1024** |    **AESGCM** | **Quant(...)esGcm [79]** |   **2.006 ms** |  **0.0399 ms** |   **0.0777 ms** |   **2.002 ms** |   **1.00** |    **0.00** |   **62.5000** |         **-** |         **-** |    **4.46 MB** |        **1.00** |
|      DefaulConnectionModeWithDataTransferAsync1024 |    AESGCM | Quant(...)esGcm [79] |   2.000 ms |  0.0524 ms |   0.1477 ms |   1.971 ms |   1.02 |    0.08 |   66.6667 |         - |         - |    4.38 MB |        0.98 |
|        DefaulConnectionModeWithDataTransfer1048576 |    AESGCM | Quant(...)esGcm [79] |   9.020 ms |  0.1790 ms |   0.4869 ms |   9.058 ms |   4.48 |    0.29 |         - |         - |         - |   18.39 MB |        4.12 |
|   DefaulConnectionModeWithDataTransferAsync1048576 |    AESGCM | Quant(...)esGcm [79] |   9.317 ms |  0.1811 ms |   0.4477 ms |   9.358 ms |   4.65 |    0.29 |         - |         - |         - |   18.31 MB |        4.10 |
|      DefaulConnectionModeWithDataTransfer104857600 |    AESGCM | Quant(...)esGcm [79] | 549.353 ms | 18.8982 ms |  55.4251 ms | 556.193 ms | 268.26 |   29.23 | 4000.0000 | 4000.0000 | 4000.0000 | 1359.59 MB |      304.51 |
| DefaulConnectionModeWithDataTransferAsync104857600 |    AESGCM | Quant(...)esGcm [79] | 563.436 ms | 10.8688 ms |   9.0760 ms | 562.236 ms | 282.51 |   13.28 | 2000.0000 | 2000.0000 | 2000.0000 | 1359.35 MB |      304.45 |
