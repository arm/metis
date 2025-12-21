# SPDX-FileCopyrightText: Copyright 2025 Arm Limited and/or its affiliates <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0

import logging
from importlib import metadata


logger = logging.getLogger("metis")


def _load_entry_point_plugins(plugin_config):
    """
    Load plugins declared via setuptools entry points (group: `metis.plugins`).

    Entry points should resolve to a class or factory that returns an instance
    implementing the BaseLanguagePlugin interface. The constructor may accept
    a single `plugin_config` argument.
    """
    plugins = []
    try:
        eps = metadata.entry_points().select(group="metis.plugins")
    except Exception as e:
        logger.debug(f"Entry point discovery failed: {e}")
        return []

    for ep in eps:
        try:
            target = ep.load()
            try:
                plugin = target(plugin_config)
            except TypeError:
                plugin = target()
            plugins.append(plugin)
            logger.debug(f"Loaded plugin from entry point: {ep.name} -> {target}")
        except Exception as e:
            logger.warning(f"Failed to load plugin entry point '{ep.name}': {e}")
    return plugins


def _load_builtin_plugins(plugin_config):
    """Fallback to built-in plugins shipped with metis.

    Import each built-in plugin independently so that a failure in one
    (e.g., optional dependencies) does not prevent others from loading.
    """
    plugins = []

    try:
        from metis.plugins.c_plugin import CPlugin

        plugins.append(CPlugin(plugin_config))
    except Exception as e:
        logger.warning(f"Failed to load built-in C plugin: {e}")

    try:
        from metis.plugins.cpp_plugin import CppPlugin

        plugins.append(CppPlugin(plugin_config))
    except Exception as e:
        logger.warning(f"Failed to load built-in C++ plugin: {e}")

    try:
        from metis.plugins.python_plugin import PythonPlugin

        plugins.append(PythonPlugin(plugin_config))
    except Exception as e:
        logger.warning(f"Failed to load built-in Python plugin: {e}")

    try:
        from metis.plugins.go_plugin import GoPlugin

        plugins.append(GoPlugin(plugin_config))
    except Exception as e:
        logger.warning(f"Failed to load built-in Go plugin: {e}")

    try:
        from metis.plugins.typescript_plugin import TypeScriptPlugin

        plugins.append(TypeScriptPlugin(plugin_config))
    except Exception as e:
        logger.warning(f"Failed to load built-in TypeScript plugin: {e}")

    try:
        from metis.plugins.solidity_plugin import SolidityPlugin

        plugins.append(SolidityPlugin(plugin_config))
    except Exception as e:
        logger.warning(f"Failed to load built-in Solidity plugin: {e}")

    try:
        from metis.plugins.rust_plugin import RustPlugin

        plugins.append(RustPlugin(plugin_config))
    except Exception as e:
        logger.warning(f"Failed to load built-in Rust plugin: {e}")

    try:
        from metis.plugins.terraform_plugin import TerraformPlugin

        plugins.append(TerraformPlugin(plugin_config))
    except Exception as e:
        logger.warning(f"Failed to load built-in Terraform plugin: {e}")

    try:
        from metis.plugins.tb_plugin import TableGenPlugin

        plugins.append(TableGenPlugin(plugin_config))
    except Exception as e:
        logger.error(f"Failed to load required TableGen plugin: {e}")
        raise

    try:
        from metis.plugins.php_plugin import PHPPlugin

        plugins.append(PHPPlugin(plugin_config))
    except Exception as e:
        logger.error(f"Failed to load required PHPPlugin plugin: {e}")
        raise

    try:
        from metis.plugins.javascript_plugin import JavaScriptPlugin

        plugins.append(JavaScriptPlugin(plugin_config))
    except Exception as e:
        logger.error(f"Failed to load required JavaScriptPlugin plugin: {e}")
        raise

    return plugins


def load_plugins(plugin_config):
    """
    Discover and instantiate Metis plugins.

    Preference order:
      1) Setuptools entry points (group `metis.plugins`)
      2) Built-in plugins bundled in this package (fallback)
    """
    plugins = _load_entry_point_plugins(plugin_config)
    if plugins:
        return plugins
    logger.info("No entry point plugins found; falling back to built-ins")
    return _load_builtin_plugins(plugin_config)


def discover_supported_language_names(plugin_config):
    """Return the list of supported language names from discovered plugins."""
    plugins = load_plugins(plugin_config)
    names = []
    for p in plugins:
        try:
            names.append(p.get_name())
        except Exception:
            continue
    return names
