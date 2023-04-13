``` ini

BenchmarkDotNet=v0.13.5, OS=Windows 11 (10.0.22621.1555/22H2/2022Update/SunValley2)
AMD Ryzen 7 5800X, 1 CPU, 16 logical and 8 physical cores
.NET SDK=7.0.101
  [Host]     : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2
  DefaultJob : .NET 7.0.1 (7.0.122.56804), X64 RyuJIT AVX2


```
|                    Method |          name |      kyberParameters |     Mean |     Error |    StdDev |     Gen0 |   Gen1 | Allocated |
|-------------------------- |-------------- |--------------------- |---------:|----------:|----------:|---------:|-------:|----------:|
| **BouncyCastleKYBERExecutor** |     **kyber1024** | **Org.B(...)eters [58]** | **3.496 ms** | **0.0156 ms** | **0.0122 ms** | **132.8125** | **3.9063** |   **2.17 MB** |
|             **KYBERExecutor** |     **kyber1024** | **Quant(...)eters [55]** | **3.407 ms** | **0.0123 ms** | **0.0115 ms** | **132.8125** | **3.9063** |   **2.16 MB** |
| **BouncyCastleKYBERExecutor** | **kyber1024-aes** | **Org.B(...)eters [58]** | **4.959 ms** | **0.0200 ms** | **0.0156 ms** | **210.9375** | **7.8125** |   **3.39 MB** |
|             **KYBERExecutor** | **kyber1024-aes** | **Quant(...)eters [55]** | **3.437 ms** | **0.0429 ms** | **0.0381 ms** | **171.8750** | **7.8125** |   **2.75 MB** |
| **BouncyCastleKYBERExecutor** |      **kyber512** | **Org.B(...)eters [58]** | **1.903 ms** | **0.0067 ms** | **0.0063 ms** | **101.5625** | **1.9531** |   **1.64 MB** |
|             **KYBERExecutor** |      **kyber512** | **Quant(...)eters [55]** | **1.879 ms** | **0.0090 ms** | **0.0079 ms** | **101.5625** | **1.9531** |   **1.63 MB** |
| **BouncyCastleKYBERExecutor** |  **kyber512-aes** | **Org.B(...)eters [58]** | **2.396 ms** | **0.0131 ms** | **0.0116 ms** | **125.0000** | **3.9063** |   **2.06 MB** |
|             **KYBERExecutor** |  **kyber512-aes** | **Quant(...)eters [55]** | **1.850 ms** | **0.0100 ms** | **0.0093 ms** | **113.2813** | **1.9531** |   **1.83 MB** |
| **BouncyCastleKYBERExecutor** |      **kyber768** | **Org.B(...)eters [58]** | **2.596 ms** | **0.0504 ms** | **0.0495 ms** | **117.1875** | **3.9063** |   **1.88 MB** |
|             **KYBERExecutor** |      **kyber768** | **Quant(...)eters [55]** | **2.543 ms** | **0.0052 ms** | **0.0040 ms** | **117.1875** | **3.9063** |   **1.87 MB** |
| **BouncyCastleKYBERExecutor** |  **kyber768-aes** | **Org.B(...)eters [58]** | **3.492 ms** | **0.0117 ms** | **0.0103 ms** | **164.0625** | **7.8125** |   **2.64 MB** |
|             **KYBERExecutor** |  **kyber768-aes** | **Quant(...)eters [55]** | **2.507 ms** | **0.0127 ms** | **0.0099 ms** | **136.7188** | **3.9063** |   **2.24 MB** |
