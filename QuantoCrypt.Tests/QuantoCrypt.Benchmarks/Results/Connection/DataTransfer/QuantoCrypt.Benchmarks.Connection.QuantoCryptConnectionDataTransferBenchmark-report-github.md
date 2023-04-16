``` ini

BenchmarkDotNet=v0.13.5, OS=Windows 11 (10.0.22621.1555/22H2/2022Update/SunValley2)
AMD Ryzen 7 5800X, 1 CPU, 16 logical and 8 physical cores
.NET SDK=7.0.101
  [Host]     : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2
  Job-OXJKBJ : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2

IterationTime=100.0000 ms  LaunchCount=1  

```
|                                                Method | targetAes | prefferedCipherSuite |       Mean |      Error |      StdDev |     Median |  Ratio | RatioSD |      Gen0 |      Gen1 |      Gen2 |  Allocated | Alloc Ratio |
|------------------------------------------------------ |---------- |--------------------- |-----------:|-----------:|------------:|-----------:|-------:|--------:|----------:|----------:|----------:|-----------:|------------:|
|         **FastShortConnectionModeWithDataTransfer102400** |       **AES** | **Quant(...)s_Aes [76]** |   **1.293 ms** |  **0.0258 ms** |   **0.0438 ms** |   **1.283 ms** |   **1.00** |    **0.00** |         **-** |         **-** |         **-** |    **4.31 MB** |        **1.00** |
|    FastShortConnectionModeWithDataTransferAsync102400 |       AES | Quant(...)s_Aes [76] |   1.299 ms |  0.0225 ms |   0.0200 ms |   1.297 ms |   1.01 |    0.03 |         - |         - |         - |    4.31 MB |        1.00 |
|        FastShortConnectionModeWithDataTransfer1048576 |       AES | Quant(...)s_Aes [76] |   8.564 ms |  0.1790 ms |   0.5277 ms |   8.649 ms |   6.59 |    0.45 |         - |         - |         - |   18.26 MB |        4.24 |
|   FastShortConnectionModeWithDataTransferAsync1048576 |       AES | Quant(...)s_Aes [76] |   8.459 ms |  0.1679 ms |   0.3959 ms |   8.507 ms |   6.56 |    0.40 |         - |         - |         - |   18.35 MB |        4.26 |
|      FastShortConnectionModeWithDataTransfer104857600 |       AES | Quant(...)s_Aes [76] | 549.854 ms | 38.1767 ms | 107.6780 ms | 587.349 ms | 433.69 |   73.98 | 2000.0000 | 2000.0000 | 2000.0000 | 1358.14 MB |      315.15 |
| FastShortConnectionModeWithDataTransferAsync104857600 |       AES | Quant(...)s_Aes [76] | 581.918 ms | 11.9138 ms |  34.5641 ms | 583.902 ms | 446.76 |   44.86 | 2000.0000 | 2000.0000 | 2000.0000 | 1358.15 MB |      315.15 |
|                                                       |           |                      |            |            |             |            |        |         |           |           |           |            |             |
|         **FastShortConnectionModeWithDataTransfer102400** |    **AESGCM** | **Quant(...)esGcm [79]** |   **1.195 ms** |  **0.0206 ms** |   **0.0192 ms** |   **1.200 ms** |   **1.00** |    **0.00** |         **-** |         **-** |         **-** |    **4.31 MB** |        **1.00** |
|    FastShortConnectionModeWithDataTransferAsync102400 |    AESGCM | Quant(...)esGcm [79] |   1.199 ms |  0.0185 ms |   0.0164 ms |   1.199 ms |   1.00 |    0.02 |         - |         - |         - |    4.31 MB |        1.00 |
|        FastShortConnectionModeWithDataTransfer1048576 |    AESGCM | Quant(...)esGcm [79] |   6.713 ms |  0.1333 ms |   0.2569 ms |   6.752 ms |   5.63 |    0.21 |         - |         - |         - |   17.14 MB |        3.98 |
|   FastShortConnectionModeWithDataTransferAsync1048576 |    AESGCM | Quant(...)esGcm [79] |   7.094 ms |  0.1416 ms |   0.3756 ms |   7.098 ms |   5.90 |    0.32 |         - |         - |         - |   17.14 MB |        3.98 |
|      FastShortConnectionModeWithDataTransfer104857600 |    AESGCM | Quant(...)esGcm [79] | 514.893 ms |  6.3824 ms |   5.3296 ms | 515.344 ms | 431.30 |    7.05 | 4000.0000 | 4000.0000 | 4000.0000 | 1358.14 MB |      315.25 |
| FastShortConnectionModeWithDataTransferAsync104857600 |    AESGCM | Quant(...)esGcm [79] | 506.208 ms |  2.8178 ms |   2.4979 ms | 506.338 ms | 423.58 |    7.11 | 2000.0000 | 2000.0000 | 2000.0000 | 1358.15 MB |      315.25 |
