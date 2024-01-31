from typing import List

from pydantic import BaseModel, Field


class PublicIP(BaseModel):
    ip: str = Field(example="192.168.1.50")
    ip_decimal: int = Field(example=3232235826)
    country: str = Field(example="United States")
    country_iso: str = Field(example="US")
    country_eu: bool = Field(example=False)
    latitude: float = Field(example=39.1033441)
    longitude: float = Field(example=-94.6721391)
    time_zone: str = Field(example="America/Chicago")
    asn: str = Field(example="AS12345")
    asn_org: str = Field(example="INTERNET")
    hostname: str = Field(example="d-192-168-1-50.paw.cpe.chicagoisp.net")


class ScanItem(BaseModel):
    ssid: str = Field(example="A Network")
    bssid: str = Field(example="11:22:33:44:55")
    keymgmt: str = Field(example="wpa-psk")
    signal: int = Field(example=-65)
    freq: int = Field(example=5650)


class ScanResults(BaseModel):
    nets: List[ScanItem]


class WlanConfig(BaseModel):
    ssid: str = Field(example="SSID Name")
    psk: str = Field(example="A_Paswword")
    key_mgmt: str = Field(example="SAE")
    ieee80211w: int = Field(example=2)


class WlanInterfaceSetup(BaseModel):
    interface: str = Field(example="wlan0")
    netConfig: WlanConfig
    removeAllFirst: bool


class NetworkSetupStatus(BaseModel):
    netId: str = Field(example="0")
    selectErr: str = Field(example="fi.w1.wpa_supplicant1.NetworkUnknown")
    connectedNet: ScanItem
    input: str


class ConnectedNetwork(BaseModel):
    connectedNet: ScanItem


class Interface(BaseModel):
    interface: str = Field(example="wlan0")


class Interfaces(BaseModel):
    interfaces: List[Interface]
