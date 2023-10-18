## IMDS Tracker

[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

IMDS Tracker is a small tracing utility powered by eBPF that analyzes IMDS requests to identify which services are making IMDS calls on a host.

### System requirements

This project was developed on an Ubuntu Jammy machine (Linux Kernel 6.2).

- golang 1.20+
- (optional) Kernel headers are expected to be installed in `lib/modules/$(uname -r)`, update the `Makefile` with their location otherwise.
- (optional) clang & llvm 11.0.1+
- (optional) libbpf-dev

Optional dependencies are required to recompile the eBPF programs.

### Build

1) Since IMDS Tracker was built using CORE, you don't need to rebuild the eBPF programs. That said, if you want to rebuild the eBPF programs anyway, you can use the following command:

```shell script
# ~ make build-ebpf
```

2) To build IMDS Tracker, run:

```shell script
# ~ make generate
# ~ make build
```

3) To install IMDS Tracker (copies the tracker to /usr/bin/imds-tracker) run:
```shell script
# ~ make install
```

### Getting started

IMDS Tracker needs to run as root. Run `sudo imds-tracker -h` to get help.

```shell script
# ~ imds-tracker -h
Usage:
  imds-tracker [flags]

Flags:
      --datadog            when set, the tracker will send the captured events to Datadog. You can configure the log sender using environment variables (see https://docs.datadoghq.com/api/latest/logs).
  -h, --help               help for imds-tracker
      --log-level string   log level of the IMDS tracker. Options are: panic, fatal, error, warn, info, debug and trace (default "info")
      --unsafe             when set, the tracker will send the entire response body of all IMDS requests instead of simply the fields known to be free of secrets or credentials.
      --vmlinux string     path to a "vmlinux" file on the system (this path should be provided only if imds-tracker can't find it by itself)
```

## License

- The golang code is under Apache 2.0 License.
- The eBPF programs are under the GPL v2 License.