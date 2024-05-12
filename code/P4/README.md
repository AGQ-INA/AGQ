# AGQ P4 program

The AGQ P4 program is written in P4-16 for the [Tofino Native Architecture (TNA)](https://github.com/barefootnetworks/Open-Tofino) and the controller uses the Barefoot Runtime Interface (BRI) to program the switch.

## 1. Requirements
The P4 code has been tested on Intel P4 Studio 9.7.0.

For details on how to obtain and compile P4 Studio, we refer you to the official [Intel documentation](https://www.intel.com/content/www/us/en/products/network-io/programmable-ethernet-switch.html).

The document [[1]](#1) provides all the instructions to compile P4 Studio (aka SDE) and a P4 program. Here we show one possible way to compile the SDE using the P4 Studio build tool.

Assuming that the `SDE` environment variable points to the SDE folder, you can use the following commands to set the environment variables:

```bash
cd bf-sde-9.7.0
source set_sde.bash
```


## 2. Running the P4 program

1. Build the P4 code. Detailed instructions are available in the Intel documentation [[1]](#1). Assuming that you are currently in the p4 directory, one way to compile the P4 program is with the following commands:

    ```bash
    mkdir build && cd build
    cmake $SDE/p4studio/ \
      -DCMAKE_INSTALL_PREFIX=$SDE/install \
      -DCMAKE_MODULE_PATH=$SDE/cmake      \
      -DP4_NAME=agq\
      -DP4_PATH=/root/AGQ-master/code/agq.p4 # replace with your path
      
    make agq
    make install
    ```



2. Run the tofino model in another terminal:
   ```bash
    $SDE/run_tofino_model.sh -p agq
    ```
3. Run the reference driver application  in another terminal:

    ```bash
    $SDE/run_switchd.sh -p agq
    ```
    Then you can configure the port according to your testbed.


## 3. Design

### 3.1 AGQ packet formats:

AGQ acts as a switch plugin, so the format is **relevant to your program and your sending method (e.g. UDP, RoCE)**.

In our example code, we use a simple packet format based on UDP like this:


| Ethernet | IPv4 | UDP | AGQ |
|--|--|--|--|

<br/>
The AGQ part contains the following fields:


| job_and_seq_ID | workerID | total_workers | data0~n | IsACK | hashID | hash1 | hash2 |
|--|--|--|--|--|--|--|--|

Note that the **hashID** equals **hash1** splicing **hash2** (e.g. **hashID**: 0b11110011, **hash1**: 0b11110, **hash2**: 0b011), since we enable multiple gradients sharing a single aggregator, the hashID specifies a seq, the hash1 specifies an aggregator, the hash2 can be used to indicate the position in an aggregator, but in the example code, we compute the position in switch, so it is just to fill the bits. For detail, pls refer to the paper.
<br/>

The P4 program does not check nor update the ICRC value, so the end-host servers should disable ICRC checking.

### 3.2 some notes for the example code
In the example code, we integrate the AGQ switch plugin in a simple INA method. For simplicity, we just use one pipe to implement all the fuctions, and aggregate 4 uint data. You can implement your INA code in another pipe to meet your need. In this example code, we integrate all the table entries in the match-action part, so you don't need to configure the tables after you run the code.

For implementation detail, pls refer to the paper.

## References
<a id="1">[1]</a> Intel® P4 Studio Software Development Environment (SDE) Installation Guide