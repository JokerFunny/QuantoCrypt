``` ini

BenchmarkDotNet=v0.13.5, OS=Windows 11 (10.0.22621.1555/22H2/2022Update/SunValley2)
AMD Ryzen 7 5800X, 1 CPU, 16 logical and 8 physical cores
.NET SDK=7.0.101
  [Host]     : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2
  Job-LEBPYF : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2

IterationTime=100.0000 ms  LaunchCount=1  

```
|                                             Method | targetAes | prefferedCipherSuite |       Mean |      Error |     StdDev |  Ratio | RatioSD |      Gen0 |      Gen1 |      Gen2 |  Allocated | Alloc Ratio |
|--------------------------------------------------- |---------- |--------------------- |-----------:|-----------:|-----------:|-------:|--------:|----------:|----------:|----------:|-----------:|------------:|
|           **DefaulConnectionModeWithDataTransfer1024** |       **AES** | **Quant(...)s_Aes [76]** |   **1.995 ms** |  **0.0461 ms** |  **0.1358 ms** |   **1.00** |    **0.00** |   **62.5000** |         **-** |         **-** |    **4.46 MB** |        **1.00** |
|      DefaulConnectionModeWithDataTransferAsync1024 |       AES | Quant(...)s_Aes [76] |   2.013 ms |  0.0399 ms |  0.1038 ms |   1.01 |    0.08 |   62.5000 |         - |         - |    4.52 MB |        1.01 |
|        DefaulConnectionModeWithDataTransfer1048576 |       AES | Quant(...)s_Aes [76] |  10.041 ms |  0.1988 ms |  0.4951 ms |   5.06 |    0.39 |         - |         - |         - |   18.33 MB |        4.11 |
|   DefaulConnectionModeWithDataTransferAsync1048576 |       AES | Quant(...)s_Aes [76] |   9.967 ms |  0.1988 ms |  0.4321 ms |   5.00 |    0.36 |         - |         - |         - |   18.37 MB |        4.12 |
|      DefaulConnectionModeWithDataTransfer104857600 |       AES | Quant(...)s_Aes [76] | 568.945 ms |  4.6369 ms |  4.3373 ms | 282.24 |   20.97 | 2000.0000 | 2000.0000 | 2000.0000 | 1359.36 MB |      305.08 |
| DefaulConnectionModeWithDataTransferAsync104857600 |       AES | Quant(...)s_Aes [76] | 576.961 ms | 17.6798 ms | 48.9907 ms | 290.99 |   32.40 | 2000.0000 | 2000.0000 | 2000.0000 | 1359.62 MB |      305.14 |
|                                                    |           |                      |            |            |            |        |         |           |           |           |            |             |
|           **DefaulConnectionModeWithDataTransfer1024** |    **AESGCM** | **Quant(...)esGcm [79]** |   **2.014 ms** |  **0.0425 ms** |  **0.1241 ms** |   **1.00** |    **0.00** |   **71.4286** |         **-** |         **-** |     **4.4 MB** |        **1.00** |
|      DefaulConnectionModeWithDataTransferAsync1024 |    AESGCM | Quant(...)esGcm [79] |   2.029 ms |  0.0403 ms |  0.1170 ms |   1.01 |    0.08 |   66.6667 |         - |         - |    4.37 MB |        0.99 |
|        DefaulConnectionModeWithDataTransfer1048576 |    AESGCM | Quant(...)esGcm [79] |   9.097 ms |  0.1804 ms |  0.4251 ms |   4.52 |    0.29 |         - |         - |         - |   18.21 MB |        4.14 |
|   DefaulConnectionModeWithDataTransferAsync1048576 |    AESGCM | Quant(...)esGcm [79] |   9.247 ms |  0.1835 ms |  0.4361 ms |   4.60 |    0.39 |         - |         - |         - |   18.43 MB |        4.19 |
|      DefaulConnectionModeWithDataTransfer104857600 |    AESGCM | Quant(...)esGcm [79] | 523.806 ms |  8.8137 ms |  7.8131 ms | 257.58 |   15.44 | 4000.0000 | 4000.0000 | 4000.0000 | 1359.26 MB |      309.06 |
| DefaulConnectionModeWithDataTransferAsync104857600 |    AESGCM | Quant(...)esGcm [79] | 523.243 ms |  4.7821 ms |  4.4732 ms | 257.55 |   14.07 | 2000.0000 | 2000.0000 | 2000.0000 | 1359.19 MB |      309.04 |
