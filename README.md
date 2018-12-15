# wemo.py

Wemo is a command-line utility and Python client class to control the
state of Belkin Wemo devices on the local network. It also works with
any device that mimics a Wemo, such as a
[Fauxmo](https://github.com/n8henrie/fauxmo). Wemo depends on Python
3.6 or later.

## Command-line use

Assuming this script is installed with the name `wemo`, here's a
synopsis of command-line usage:

`wemo discover [interface]` queries the network (on all available
interfaces unless one interface is specified) and prints a list of
devices found, including their IP addresses, ports, and names.

`wemo "Kitchen Lights" on` finds a Wemo named "Kitchen Lights" and
turns it on.

`wemo 192.168.0.200 toggle` finds the Wemo located at the IP address
`192.168.0.200` and toggles its state (e.g., turns it off if it was
on, and vice versa)

`wemo "Living Room Lights" getstate` returns the current state of the
Wemo named "Living Room Lights": True if on, False otherwise

`wemo help` gives a full usage message.

## Calling from Python

If you import wemo.py into your own Python project, you will mainly
interact through the Wemo object. See the docs for details.

## Testing

A small suite of pytest tests is provided, but unfortunately the test
suite assumes details about the setup of Wemo devices on your
network. Edit the list at the top of `test_wemo.py` to make it
specific to your own network, and then run `python -m pytest`.
