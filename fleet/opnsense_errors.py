class DeviceError(Exception):
    """A firewall API failure, worded for the person reading it. `status_code` is set for HTTP errors."""

    def __init__(self, message, status_code=None):
        super().__init__(message)
        self.status_code = status_code


class SavepointUnsupported(DeviceError):
    """The firewall has no filter savepoint API (removed in OPNsense 26.7)."""
