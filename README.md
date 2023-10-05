# Distrusted Dealers: Efficient Secure (n+1)-Party Computation

In this repository we provide our implementation the paper.
This code has been primarily tested on Linux system based on recent versions of Arch Linux.
It has also been found to work on MacBooks to some extent.

Assuming a nightly version of Rust is installed the code benchmarks can be run easily using `cargo bench`.

The code contains many benchmarks, some unrelated directly to the paper and therefore we focus on the ones related to the results we presented in the paper.

These are available in two different benchmarks: One of a the SPDZ-based protocol with a dealer and the other of the FLIOP-based protocol.

Running our benchmarks on a single core for the AES circuit with malicious security can be done using:

`RAYON_NUM_THREADS=1 cargo bench --bench "circuit_eval"  -- "aes malicious packed 1"`

The number of threads is specified by the `RAYON_NUM_THREADS` environment variable. Unless overriden we use all available cores.

The SPDZ-based approach's benchmark can be run using:

`cargo bench --bench spdz`

Both benchmarks are run and output different time measurements along their execution as well as a final measurement at the end of execution.

To look at other benchamrks one can run the command:

`cargo bench --bench` 

which provides a list of available benchmarks.

## Networking Setup
Our benchmark works over local area network interface (despite nothing prevents it in a general networking setting, but it might require however more work to set up the environment and to provide accurate measurements).
As explained in the paper, we simulate the networking environment using `tc qdisc` command on Linux. 
Other platforms do not provide simple mechanisms to simulate such networks efficiently.
As part of the code we provide the `set_networking.sh` bash script which when run can set up the networking environment specified inside the document.
By default it is currently set to a 2Gbps network with 0.1ms latency and these can easily be changed by editing the file itself and re-running the script.
