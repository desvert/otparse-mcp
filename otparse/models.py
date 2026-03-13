from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


class ToolMetadata(BaseModel):
    pcap_path: str = Field(description="PCAP file analyzed")
    packet_count: int = Field(default=0)
    notes: list[str] = Field(default_factory=list)


class ModbusTransaction(BaseModel):
    frame_number: int
    timestamp: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    transaction_id: int | None = None
    unit_id: int | None = None
    function_code: int | None = None
    function_name: str | None = None
    reference_number: int | None = None
    word_count: int | None = None
    bit_count: int | None = None
    data: list[int] = Field(default_factory=list)
    raw_summary: str | None = None
    direction: Literal["request", "response", "unknown"] = "unknown"


class ModbusParseResult(BaseModel):
    protocol: Literal["modbus"] = "modbus"
    metadata: ToolMetadata
    transactions: list[ModbusTransaction] = Field(default_factory=list)


class BacnetPacket(BaseModel):
    frame_number: int
    timestamp: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    bvlc_function: str | None = None
    npdu_control: str | None = None
    apdu_type: str | None = None
    service: str | None = None
    invoke_id: int | None = None
    object_type: str | None = None
    object_instance: int | None = None
    property_identifier: str | None = None
    raw_summary: str | None = None


class BacnetParseResult(BaseModel):
    protocol: Literal["bacnet"] = "bacnet"
    metadata: ToolMetadata
    packets: list[BacnetPacket] = Field(default_factory=list)


class DeviceRecord(BaseModel):
    ip: str
    protocols: list[str] = Field(default_factory=list)
    ports: list[int] = Field(default_factory=list)
    hints: list[str] = Field(default_factory=list)


class DeviceInventory(BaseModel):
    devices: list[DeviceRecord] = Field(default_factory=list)


class ErrorResult(BaseModel):
    error: str
    details: dict[str, Any] = Field(default_factory=dict)
