# UDP DNS Query Analyzer

This is a Linux kernel module that analyzes UDP DNS queries. It hooks into the Netfilter framework to capture DNS query packets, extracts the domain name (QNAME), and prints the query details to the kernel log.

## Features

- Captures DNS queries on UDP port 53.
- Parses the QNAME from the DNS payload.
- Logs the source IP, destination IP, and queried domain name via `printk`.
- Ignores non-query DNS packets and compressed DNS pointers for simplicity.

## Requirements

- A Linux system with kernel headers installed.
- `make` and a C compiler (like GCC).

## How to Build

Simply run the `make` command in the project directory:

```sh
make
```

This will produce the kernel module file `packet_capture.ko`.

## How to Use

1.  **Load the module:**
    ```sh
    sudo insmod packet_capture.ko
    ```

2.  **View the logs:**
    You can see the output in the kernel log. Use `dmesg` to view it:
    ```sh
    dmesg -w
    ```
    When a DNS query occurs on the system, a log entry like the following will appear:
    ```
    [DNS Query] src: 192.168.1.10 dst: 8.8.8.8 QNAME: www.google.com
    ```

3.  **Unload the module:**
    ```sh
    sudo rmmod packet_capture
    ```

## License

This project is licensed under the **GPL v2**. See the [LICENSE](LICENSE) file for details.
