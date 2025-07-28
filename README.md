# UDP DNS Query Analyzer

This is a Linux kernel module that analyzes UDP DNS queries. It hooks into the Netfilter framework to capture DNS query packets, extracts the domain name (QNAME), and prints the query details to the kernel log.

## Features

- Captures DNS queries on UDP port 53.
- Parses the QNAME from the DNS payload.
- Logs the source IP, destination IP, and queried domain name via `printk`.
- Ignores non-query DNS packets and compressed DNS pointers for simplicity.

## Prerequisites

To build this kernel module, you need the kernel headers for your specific kernel version. Here’s how to install them on common Linux distributions.

### Debian / Ubuntu / Raspberry Pi OS

Open a terminal and run the following command:

```sh
sudo apt update
sudo apt install linux-headers-$(uname -r)
```

### RHEL / CentOS / Fedora

Open a terminal and run the following command. Use `dnf` for modern systems (Fedora, RHEL 8+) or `yum` for older systems (CentOS 7, RHEL 7).

**Using DNF:**
```sh
sudo dnf install kernel-devel-$(uname -r)
```

**Using YUM:**
```sh
sudo yum install kernel-devel-$(uname -r)
```

## Build Requirements

- `make` and a C compiler (like GCC). These are typically installed via the `build-essential` package on Debian/Ubuntu or "Development Tools" group on RHEL/CentOS.

## How to Build

Simply run the `make` command in the project directory:

```sh
make
```

This will produce the kernel module file `dns_query_analyzer.ko`.

## How to Use

You can load and unload the module using `make` commands or by manually using `insmod`/`rmmod`.

### Using Make (Recommended)

- **Load the module:**
  ```sh
  sudo make install
  ```

- **Unload the module:**
  ```sh
  sudo make uninstall
  ```

### Manual Method

1.  **Load the module:**
    ```sh
    sudo insmod dns_query_analyzer.ko
    ```

2.  **Unload the module:**
    ```sh
    sudo rmmod dns_query_analyzer
    ```

### View the Logs

You can see the output in the kernel log, regardless of the installation method. Use `dmesg` to view it:
```sh
dmesg -w
```
When a DNS query occurs on the system, a log entry like the following will appear:
```
[DNS Query] src: 192.168.1.10 dst: 8.8.8.8 QNAME: www.google.com
```

### How to Log to a Dedicated File (using rsyslog)

By default, the module logs to the standard kernel log (`dmesg`). If you want to redirect these logs to a separate file, you can use `rsyslog`. This module uses the `local0` facility, allowing for easy filtering.

#### 1. Configure rsyslog

Create a new configuration file to tell `rsyslog` where to save the logs.

```sh
sudo bash -c 'cat > /etc/rsyslog.d/50-dns-analyzer.conf << EOL
# Rule for DNS Query Analyzer
if \$syslogfacility-text == 'local0' then /var/log/dns_query.log
& ~
EOL'
```
This rule directs all logs from `local0` to `/var/log/dns_query.log` and stops them from appearing in other log files.

#### 2. Restart rsyslog

Apply the new configuration by restarting the `rsyslog` service.

```sh
sudo systemctl restart rsyslog
```

Now, you can monitor the dedicated log file:
```sh
tail -f /var/log/dns_query.log
```

#### 3. (Recommended) Set Up Log Rotation

To prevent the log file from growing indefinitely, it is highly recommended to set up log rotation. Create a `logrotate` configuration file:

```sh
sudo bash -c 'cat > /etc/logrotate.d/dns_query << EOL
/var/log/dns_query.log
{
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 0640 root adm
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate >/dev/null 2>&1 || true
    endscript
}
EOL'
```
This configuration will rotate the logs daily, compress them, and keep the last 7 days of archives.

## License

This project is licensed under the **GPL v2**. See the [LICENSE](LICENSE) file for details.
