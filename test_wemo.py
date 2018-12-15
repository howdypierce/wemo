"""test_wemo.py :: Tests for wemo utility."""

import pytest
import wemo

# A HUGE problem right now is that these tests are tied to the setup
# of my home environment. Ideally I would mock this out but this is
# what we've got for now.
#
# Below, fill in a list of actual wemos and fauxmos available on the
# network, listed by the tuple (Friendly Name, IP Address, Port).
# These devices must exist and must respond like wemos repond, or the
# tests will fail

wemos = [("Family Room Lights", "192.168.87.67", 49153),
         ("Garage Lights", "192.168.87.68", 49153),
         ("Bedroom Light", "192.168.87.73", 49915)]

nonresponsive_ip = "192.168.87.10"  # a non-responsive address on our network


def test_discovery() -> None:
    """Test SSDP discovery.

    Run an SSDP discovery, and ensure that every device in wemos is
    listed.  Doesn't call the Wemo class, and therefore this test
    doesn't verify friendly names.
    """
    ret = wemo.ssdp_discover("urn:Belkin:device:**", timeout=3, retries=3)
    print([(r.host, r.port) for r in ret])

    for wm in wemos:
        assert any([(r.host == wm[1] and r.port == str(wm[2])) for r in ret])

def test_create_by_name() -> None:
    """Test finding Wemos by name.

    Ensure that we can toggle the returned device twice.
    """
    for wm in wemos:
        w = wemo.Wemo(name=wm[0])
        ret1 = w.do("toggle")
        assert(w.ip == wm[1] and w.port == wm[2])
        assert(w.get_state() == ret1)
        ret2 = w.toggle()
        assert(ret1 == (not ret2))

def test_create_by_ipaddr() -> None:
    """Test finding Wemos by IP address."""
    for wm in wemos:
        w = wemo.Wemo(wm[1], wm[2])
        init_state = w.get_state()
        w.do("on")
        assert(w.get_state() == True)
        w.set_state(init_state)
        assert(w.get_name() == wm[0])

def test_wrong_port() -> None:
    """Test creating a Wemo at an incorrect port (but valid IP address)"""
    wm = wemos[0]
    w = wemo.Wemo(wm[1], int(wm[2]) + 254)
    with pytest.raises(Exception) as excinfo:
        w.get_name()
    assert ("Timeout on ports" in str(excinfo.value))

def test_auto_port_finding() -> None:
    """Test allowing default ports.

    Note this only works if the actual port is in the list [49153,
    49152, 49154, 49151, 49155]
    """
    default_wemo_ports = [49153, 49152, 49154, 49151, 49155]
    for wm in wemos:
        if wm[2] not in default_wemo_ports:
            continue
        w = wemo.Wemo(wm[1])
        assert(30 <= w.get_signal_strength() <= 110)

def test_bad_ip() -> None:
    """Test creating a Wemo at a nonresponsive IP address"""
    w = wemo.Wemo(nonresponsive_ip)
    with pytest.raises(Exception) as excinfo:
        w.get_name()
    assert ("Timeout on ports" in str(excinfo.value))

def test_bad_name() -> None:
    """Test creating a Wemo by name that doesn't exist"""
    bad_name = "Ralph"
    w = wemo.Wemo(name=bad_name)
    assert(w.get_name() == bad_name)
    with pytest.raises(Exception) as excinfo:
        w.get_state()
    assert (f"Unable to find Wemo by name {bad_name}" in str(excinfo.value))
