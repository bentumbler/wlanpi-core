import asyncio
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from wlanpi_core.api.api_v1.endpoints import network_config_api
from wlanpi_core.utils import network_config


def test_get_status_uses_to_thread(mocker):
    to_thread = mocker.patch.object(
        network_config_api.asyncio,
        "to_thread",
        new=AsyncMock(return_value={"root": {}}),
    )

    result = asyncio.run(network_config_api.get_status())

    to_thread.assert_awaited_once_with(network_config.status)
    assert result == {"root": {}}


def test_get_configs_uses_to_thread(mocker):
    to_thread = mocker.patch.object(
        network_config_api.asyncio,
        "to_thread",
        new=AsyncMock(return_value={"lab_cfg": False}),
    )

    result = asyncio.run(network_config_api.get_configs())

    to_thread.assert_awaited_once_with(network_config.list_configs)
    assert result == {"lab_cfg": False}


def test_activate_config_uses_to_thread(mocker):
    connections = [{"conn_id": "conn_3f9a1c2e", "iface": "wlan1", "namespace": "ns_sta"}]
    to_thread = mocker.patch.object(
        network_config_api.asyncio,
        "to_thread",
        new=AsyncMock(return_value=network_config.ActivationResult(True, connections)),
    )

    result = asyncio.run(
        network_config_api.activate_config("lab_cfg", override_active=True)
    )

    to_thread.assert_awaited_once_with(
        network_config.activate_config_with_result, "lab_cfg", True, None
    )
    assert result == {
        "id": "lab_cfg",
        "message": "Configuration activated successfully",
        "connections": connections,
    }


def test_activate_config_passes_debug_level_override(mocker):
    to_thread = mocker.patch.object(
        network_config_api.asyncio,
        "to_thread",
        new=AsyncMock(return_value=network_config.ActivationResult(True)),
    )

    result = asyncio.run(
        network_config_api.activate_config("lab_cfg", override_active=False, debug_level=1)
    )

    to_thread.assert_awaited_once_with(
        network_config.activate_config_with_result, "lab_cfg", False, 1
    )
    assert result["connections"] == []


def test_activate_config_failure_is_500(mocker):
    mocker.patch.object(
        network_config_api.asyncio,
        "to_thread",
        new=AsyncMock(return_value=network_config.ActivationResult(False)),
    )
    with pytest.raises(HTTPException) as excinfo:
        asyncio.run(network_config_api.activate_config("lab_cfg"))
    assert excinfo.value.status_code == 500


def test_deactivate_config_uses_to_thread(mocker):
    to_thread = mocker.patch.object(
        network_config_api.asyncio,
        "to_thread",
        new=AsyncMock(return_value=True),
    )

    result = asyncio.run(
        network_config_api.deactivate_config("lab_cfg", override_active=True)
    )

    to_thread.assert_awaited_once_with(
        network_config.deactivate_config,
        "lab_cfg",
        override_active=True,
    )
    assert result == {
        "id": "lab_cfg",
        "message": "Configuration deactivated successfully",
    }


def test_deactivate_config_normalizes_override_active(mocker):
    to_thread = mocker.patch.object(
        network_config_api.asyncio,
        "to_thread",
        new=AsyncMock(return_value=True),
    )

    asyncio.run(network_config_api.deactivate_config("lab_cfg", override_active=False))

    to_thread.assert_awaited_once_with(
        network_config.deactivate_config,
        "lab_cfg",
        override_active=False,
    )
