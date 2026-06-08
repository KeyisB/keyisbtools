import msgpack
from typing import Union, List, Dict, TypeAlias, Any
import datetime

SerializableKey = Union[str, bytes, int]

SerializableType: TypeAlias = Union[
    None,
    bool,
    int,
    float,
    str,
    bytes,
    List[Any], # List["SerializableType"],
    Dict[Any, Any], # Dict[SerializableKey, "SerializableType"],
    datetime.datetime
]




def serialize(data: SerializableType) -> bytes:
    return msgpack.packb(data, use_bin_type=True, datetime=True) # type: ignore

_JS_BYTES_EXT_CODES = frozenset({
    17,  # Int8Array
    18,  # Uint8Array
    19,  # Int16Array
    20,  # Uint16Array
    21,  # Int32Array
    22,  # Uint32Array
    23,  # Float32Array
    24,  # Float64Array
    25,  # Uint8ClampedArray
    26,  # ArrayBuffer
    27,  # Buffer
    29,  # DataView
})

def deserialize(data: bytes, raw_str: bool = False) -> SerializableType:
    return msgpack.unpackb(
        data,
        strict_map_key=False,
        raw=raw_str,
        timestamp=3,
        ext_hook=lambda code, payload: payload if code in _JS_BYTES_EXT_CODES else msgpack.ExtType(code, payload),
    )


