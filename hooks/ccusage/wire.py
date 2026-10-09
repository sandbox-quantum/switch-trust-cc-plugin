"""Minimal, stdlib-only protobuf binary wire-format encoder.

Not a general protobuf implementation -- it encodes exactly the small, fixed
set of message shapes this plugin sends (see events.py), using plain
varint/tag/length-delimited primitives per the protobuf wire-format spec.
Byte-for-byte correctness against the real backend schema is verified by
tests/test_wire_compatibility.py.

Every field builder here writes unconditionally -- callers only pass a value
for a field when they intend to send it -- except `timestamp_field`, which
omits a zero `seconds`/`nanos` to match the real schema's implicit-presence
`google.protobuf.Timestamp` fields.
"""

from __future__ import annotations

_WIRE_TYPE_VARINT = 0
_WIRE_TYPE_LEN = 2


def varint(value: int) -> bytes:
    """Encode a non-negative integer as a protobuf varint."""
    if value < 0:
        raise ValueError("varint() does not support negative values")
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def tag(field_number: int, wire_type: int) -> bytes:
    """Encode a field tag: `(field_number << 3) | wire_type`."""
    return varint((field_number << 3) | wire_type)


def varint_field(field_number: int, value: int) -> bytes:
    """Encode a varint-typed field (used here for enums and token counts)."""
    return tag(field_number, _WIRE_TYPE_VARINT) + varint(value)


def len_delimited_field(field_number: int, data: bytes) -> bytes:
    """Encode a length-delimited field (used for strings and embedded messages)."""
    return tag(field_number, _WIRE_TYPE_LEN) + varint(len(data)) + data


def string_field(field_number: int, value: str) -> bytes:
    """Encode a UTF-8 string field; a lone surrogate is sent as `?` rather than raising."""
    return len_delimited_field(field_number, value.encode("utf-8", "replace"))


def message_field(field_number: int, submessage_bytes: bytes) -> bytes:
    """Encode an embedded message field (an alias of `len_delimited_field` for readability)."""
    return len_delimited_field(field_number, submessage_bytes)


def timestamp_field(field_number: int, epoch_seconds: int, nanos: int) -> bytes:
    """Encode a `google.protobuf.Timestamp` submessage (`{seconds=1, nanos=2}`).

    Both subfields use implicit presence in the real schema, so a zero value
    is omitted entirely rather than encoded as an explicit zero -- this
    matters in practice since a whole-second timestamp has `nanos == 0`.
    """
    body = b""
    if epoch_seconds:
        body += varint_field(1, epoch_seconds)
    if nanos:
        body += varint_field(2, nanos)
    return message_field(field_number, body)


def varint_prefixed(data: bytes) -> bytes:
    """Prepend a varint-encoded length to `data`, for length-delimited streaming."""
    return varint(len(data)) + data
