from pydantic import BaseModel, Field


class ServiceStatus(BaseModel):
    name: str = Field(example="wlanpi-fpms")
    active: bool = Field(example=True)


class ServiceRunning(BaseModel):
    name: str = Field(example="wlanpi-fpms")
    running: bool = Field(example=True)


class Hostname(BaseModel):
    hostname: str = Field(example="wlanpi-2ee")


class SystemInfo(BaseModel):
    system: str = Field(example="Linux")
    build: str = Field(example="3.1.1")
    node_name: str = Field(example="wlanpi")
    release: str = Field(example="5.4.48-sunxi64")
    version: str = Field(example="#trunk SMP Wed Jun 24 00:42:17 -03 2020")
    machine: str = Field(example="aarch64")
    hardware: str = Field(example="BCM2835")
