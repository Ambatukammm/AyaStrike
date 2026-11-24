"""Core framework services for AyaStrike.

This package holds everything that is NOT a pentest module: configuration,
project workspaces, the target-scope whitelist, audit logging, rate limiting,
the plugin registry, the safe subprocess runner, and the authorisation gate.

Modules depend on core; core never depends on modules.
"""
