"""Pentest modules, organised by lifecycle phase.

Every module subclasses :class:`aya.modules.base.BaseModule` and registers
itself via the ``@register`` decorator. The GUI and the plugin loader discover
modules purely through the registry, so adding a new capability is as simple as
dropping a new file in the right phase package and subclassing BaseModule.
"""
