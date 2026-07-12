from typing import Annotated, TypedDict

import ida_typeinf
import ida_hexrays
import ida_nalt
import ida_bytes
import ida_frame
import ida_ida
import ida_ua
import idaapi
import idautils
import idc

from .rpc import tool
from .sync import idasync, ida_major, tool_timeout
from .utils import (
    normalize_list_input,
    normalize_dict_list,
    parse_address,
    get_type_by_name,
    parse_decls_ctypes,
    my_modifier_t,
    StructureMember,
    StructureDefinition,
    StructRead,
    TypeEdit,
    read_bytes_bss_safe,
    read_int_bss_safe,
)


# ============================================================================
# Type Declaration
# ============================================================================


@tool
@idasync
def declare_type(
    decls: Annotated[list[str] | str, "C type declarations"],
) -> list[dict]:
    """Declare types"""
    decls = normalize_list_input(decls)
    results = []

    for decl in decls:
        try:
            flags = ida_typeinf.PT_SIL | ida_typeinf.PT_EMPTY | ida_typeinf.PT_TYP
            errors, messages = parse_decls_ctypes(decl, flags)

            pretty_messages = "\n".join(messages)
            if errors > 0:
                results.append(
                    {"decl": decl, "error": f"Failed to parse:\n{pretty_messages}"}
                )
            else:
                results.append({"decl": decl, "ok": True})
        except Exception as e:
            results.append({"decl": decl, "error": str(e)})

    return results


# ============================================================================
# Structure Operations
# ============================================================================


@tool
@idasync
def read_struct(queries: list[StructRead] | StructRead) -> list[dict]:
    """Reads struct type definition and parses actual memory values at the
    given address as instances of that struct type.

    If struct name is not provided, attempts to auto-detect from address.
    Auto-detection only works if IDA already has type information applied
    at that address

    Returns struct layout with actual memory values for each field.
    """

    queries = normalize_dict_list(queries)

    results = []
    for query in queries:
        addr_str = query.get("addr", "")
        struct_name = query.get("struct", "")

        try:
            # Parse address - this is required
            if not addr_str:
                results.append(
                    {
                        "addr": None,
                        "struct": struct_name,
                        "members": None,
                        "error": "Address is required for reading struct fields",
                    }
                )
                continue

            try:
                addr = parse_address(addr_str)
            except Exception:
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": f"Failed to resolve address: {addr_str}",
                    }
                )
                continue

            # Auto-detect struct type from address if not provided
            if not struct_name:
                tif_auto = ida_typeinf.tinfo_t()
                if ida_nalt.get_tinfo(tif_auto, addr) and tif_auto.is_udt():
                    struct_name = tif_auto.get_type_name()

            if not struct_name:
                results.append(
                    {
                        "addr": addr_str,
                        "struct": None,
                        "members": None,
                        "error": "No struct specified and could not auto-detect from address",
                    }
                )
                continue

            tif = ida_typeinf.tinfo_t()
            if not tif.get_named_type(None, struct_name):
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": f"Struct '{struct_name}' not found",
                    }
                )
                continue

            udt_data = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt_data):
                results.append(
                    {
                        "addr": addr_str,
                        "struct": struct_name,
                        "members": None,
                        "error": "Failed to get struct details",
                    }
                )
                continue

            members = []
            for member in udt_data:
                offset = member.begin() // 8
                member_type = member.type._print()
                member_name = member.name
                member_size = member.type.get_size()

                # Read memory value at member address
                member_addr = addr + offset
                try:
                    if member.type.is_ptr():
                        from . import compat
                        is_64bit = compat.inf_is_64bit()
                        ptr_size = 8 if is_64bit else 4
                        value = read_int_bss_safe(member_addr, ptr_size)
                        value_str = f"0x{value:0{ptr_size * 2}X}"
                    elif member_size in (1, 2, 4, 8):
                        value = read_int_bss_safe(member_addr, member_size)
                        value_str = f"0x{value:0{member_size * 2}X} ({value})"
                    else:
                        bytes_data = [
                            f"{byte:02X}"
                            for byte in read_bytes_bss_safe(member_addr, min(member_size, 16))
                        ]
                        value_str = f"[{' '.join(bytes_data)}{'...' if member_size > 16 else ''}]"
                except Exception:
                    value_str = "<failed to read>"

                member_info = {
                    "offset": f"0x{offset:08X}",
                    "type": member_type,
                    "name": member_name,
                    "size": member_size,
                    "value": value_str,
                }

                members.append(member_info)

            results.append(
                {"addr": addr_str, "struct": struct_name, "members": members}
            )
        except Exception as e:
            results.append(
                {
                    "addr": addr_str,
                    "struct": struct_name,
                    "members": None,
                    "error": str(e),
                }
            )

    return results


@tool
@idasync
def search_structs(
    filter: Annotated[
        str, "Case-insensitive substring to search for in structure names"
    ],
) -> list[dict]:
    """Search structs"""
    results = []
    limit = ida_typeinf.get_ordinal_limit()

    for ordinal in range(1, limit):
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(None, ordinal):
            type_name: str = tif.get_type_name()
            if type_name and filter.lower() in type_name.lower():
                if tif.is_udt():
                    udt_data = ida_typeinf.udt_type_data_t()
                    cardinality = 0
                    if tif.get_udt_details(udt_data):
                        cardinality = udt_data.size()

                    results.append(
                        {
                            "name": type_name,
                            "size": tif.get_size(),
                            "cardinality": cardinality,
                            "is_union": (
                                udt_data.is_union
                                if tif.get_udt_details(udt_data)
                                else False
                            ),
                            "ordinal": ordinal,
                        }
                    )

    return results


# ============================================================================
# Type Inference & Application
# ============================================================================


@tool
@idasync
def set_type(edits: list[TypeEdit] | TypeEdit) -> list[dict]:
    """Apply types (function/global/local/stack)"""

    def parse_addr_type(s: str) -> dict:
        # Support "addr:typename" format (auto-detects kind)
        if ":" in s:
            parts = s.split(":", 1)
            return {"addr": parts[0].strip(), "ty": parts[1].strip()}
        # Just typename without address (invalid)
        return {"ty": s.strip()}

    edits = normalize_dict_list(edits, parse_addr_type)
    results = []

    for edit in edits:
        try:
            # Auto-detect kind if not provided
            kind = edit.get("kind")
            if not kind:
                if "signature" in edit:
                    kind = "function"
                elif "variable" in edit:
                    kind = "local"
                elif "addr" in edit:
                    # Check if address points to a function
                    try:
                        addr = parse_address(edit["addr"])
                        func = idaapi.get_func(addr)
                        if func and "name" in edit and "ty" in edit:
                            kind = "stack"
                        else:
                            kind = "global"
                    except Exception:
                        kind = "global"
                else:
                    kind = "global"

            if kind == "function":
                func = idaapi.get_func(parse_address(edit["addr"]))
                if not func:
                    results.append({"edit": edit, "error": "Function not found"})
                    continue

                tif = ida_typeinf.tinfo_t(edit["signature"], None, ida_typeinf.PT_SIL)
                if not tif.is_func():
                    results.append({"edit": edit, "error": "Not a function type"})
                    continue

                success = ida_typeinf.apply_tinfo(
                    func.start_ea, tif, ida_typeinf.PT_SIL
                )
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "global":
                ea = idaapi.get_name_ea(idaapi.BADADDR, edit.get("name", ""))
                if ea == idaapi.BADADDR:
                    ea = parse_address(edit["addr"])

                tif = get_type_by_name(edit["ty"])
                success = ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.PT_SIL)
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "local":
                func = idaapi.get_func(parse_address(edit["addr"]))
                if not func:
                    results.append({"edit": edit, "error": "Function not found"})
                    continue

                new_tif = ida_typeinf.tinfo_t(edit["ty"], None, ida_typeinf.PT_SIL)
                modifier = my_modifier_t(edit["variable"], new_tif)
                success = ida_hexrays.modify_user_lvars(func.start_ea, modifier)
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to apply type",
                    }
                )

            elif kind == "stack":
                func = idaapi.get_func(parse_address(edit["addr"]))
                if not func:
                    results.append({"edit": edit, "error": "No function found"})
                    continue

                frame_tif = ida_typeinf.tinfo_t()
                if not ida_frame.get_func_frame(frame_tif, func):
                    results.append({"edit": edit, "error": "No frame"})
                    continue

                idx, udm = frame_tif.get_udm(edit["name"])
                if not udm:
                    results.append({"edit": edit, "error": f"{edit['name']} not found"})
                    continue

                tid = frame_tif.get_udm_tid(idx)
                udm = ida_typeinf.udm_t()
                frame_tif.get_udm_by_tid(udm, tid)
                offset = udm.offset // 8

                tif = get_type_by_name(edit["ty"])
                success = ida_frame.set_frame_member_type(func, offset, tif)
                results.append(
                    {
                        "edit": edit,
                        "ok": success,
                        "error": None if success else "Failed to set type",
                    }
                )

            else:
                results.append({"edit": edit, "error": f"Unknown kind: {kind}"})

        except Exception as e:
            results.append({"edit": edit, "error": str(e)})

    return results


@tool
@idasync
def infer_types(
    addrs: Annotated[list[str] | str, "Addresses to infer types for"],
) -> list[dict]:
    """Infer types"""
    addrs = normalize_list_input(addrs)
    results = []

    for addr in addrs:
        try:
            ea = parse_address(addr)
            tif = ida_typeinf.tinfo_t()

            # Try Hex-Rays inference
            if ida_hexrays.init_hexrays_plugin() and ida_hexrays.guess_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "hexrays",
                        "confidence": "high",
                    }
                )
                continue

            # Try getting existing type info
            if ida_nalt.get_tinfo(tif, ea):
                results.append(
                    {
                        "addr": addr,
                        "inferred_type": str(tif),
                        "method": "existing",
                        "confidence": "high",
                    }
                )
                continue

            # Try to guess from size
            size = ida_bytes.get_item_size(ea)
            if size > 0:
                type_guess = {
                    1: "uint8_t",
                    2: "uint16_t",
                    4: "uint32_t",
                    8: "uint64_t",
                }.get(size, f"uint8_t[{size}]")

                results.append(
                    {
                        "addr": addr,
                        "inferred_type": type_guess,
                        "method": "size_based",
                        "confidence": "low",
                    }
                )
                continue

            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                }
            )

        except Exception as e:
            results.append(
                {
                    "addr": addr,
                    "inferred_type": None,
                    "method": None,
                    "confidence": "none",
                    "error": str(e),
                }
            )

    return results


# ============================================================================
# Enum Upsert — idempotent enum creation/update
# ============================================================================


def _parse_enum_value(raw) -> int:
    """Parse an enum member value from int, str ('0x...', decimal), or None."""
    if raw is None:
        raise ValueError("Enum member value is required")
    if isinstance(raw, int):
        return raw
    s = str(raw).strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


@tool
@idasync
def enum_upsert(
    queries: Annotated[list[dict] | dict,
        "Enum upsert: name, members [{name, value}], bitfield (optional bool)"],
) -> list[dict]:
    """Create or extend local enums in an idempotent way. Creates the enum if
    it doesn't exist, then upserts each member: skips if name+value already match,
    reports conflict if name or value collides with a different entry. Never
    destructively replaces existing members."""
    queries = normalize_dict_list(queries)
    results = []

    for query in queries:
        enum_name = str(query.get("name", "") or "").strip()
        members = normalize_dict_list(query.get("members"))
        bitfield = bool(query.get("bitfield", False))

        if not enum_name:
            results.append({"name": enum_name, "error": "Enum name is required"})
            continue
        if not members or members == [{}]:
            results.append({"name": enum_name, "error": "At least one member is required"})
            continue

        try:
            enum_id = idc.get_enum(enum_name)
            created = enum_id == idc.BADADDR
            if created:
                enum_id = idc.add_enum(idc.BADADDR, enum_name, 0)
                if enum_id == idc.BADADDR:
                    results.append({"name": enum_name, "error": f"Failed to create enum: {enum_name}"})
                    continue

            if bool(idc.is_bf(enum_id)) != bitfield and not created:
                results.append({"name": enum_name, "enum_id": hex(enum_id),
                                "error": f"Enum bitfield mismatch for {enum_name}"})
                continue
            idc.set_enum_bf(enum_id, bitfield)

            member_results = []
            created_count = skipped_count = conflict_count = 0

            for member in members:
                member_name = str(member.get("name", "") or "").strip()
                if not member_name:
                    member_results.append({"name": "", "error": "Member name is required"})
                    conflict_count += 1
                    continue
                try:
                    value = _parse_enum_value(member.get("value"))
                except Exception as exc:
                    member_results.append({"name": member_name, "error": str(exc)})
                    conflict_count += 1
                    continue

                existing_mid = idc.get_enum_member_by_name(member_name)
                if existing_mid != idc.BADADDR:
                    existing_enum = idc.get_enum_member_enum(existing_mid)
                    existing_value = idc.get_enum_member_value(existing_mid)
                    if existing_enum == enum_id and existing_value == value:
                        member_results.append({"name": member_name, "value": value, "skipped": True})
                        skipped_count += 1
                        continue
                    member_results.append({
                        "name": member_name, "value": value,
                        "error": f"Name conflict: {member_name} exists with value {existing_value}",
                    })
                    conflict_count += 1
                    continue

                existing_const = idc.get_enum_member(enum_id, value, 0, -1)
                if existing_const != -1:
                    existing_name = idc.get_enum_member_name(existing_const) or ""
                    if existing_name == member_name:
                        member_results.append({"name": member_name, "value": value, "skipped": True})
                        skipped_count += 1
                        continue
                    member_results.append({
                        "name": member_name, "value": value,
                        "error": f"Value conflict: {value} belongs to {existing_name}",
                    })
                    conflict_count += 1
                    continue

                rc = idc.add_enum_member(enum_id, member_name, value, -1)
                if rc != 0:
                    member_results.append({"name": member_name, "value": value,
                                           "error": f"add_enum_member failed: rc={rc}"})
                    conflict_count += 1
                    continue
                member_results.append({"name": member_name, "value": value, "created": True})
                created_count += 1

            result_dict: dict = {
                "name": enum_name, "enum_id": hex(enum_id), "created": created,
                "bitfield": bitfield, "members": member_results,
                "summary": {"created": created_count, "skipped": skipped_count, "conflicts": conflict_count},
            }
            if conflict_count > 0:
                result_dict["error"] = f"{conflict_count} member conflict(s)"
            results.append(result_dict)
        except Exception as exc:
            results.append({"name": enum_name, "error": str(exc)})

    return results


# ============================================================================
# struct_infer — aggregate [base+disp] access patterns
# ============================================================================

_STRUCT_INFER_MAX_FIELDS = 200

_RMW_MNEMS = frozenset({
    "add", "sub", "and", "or", "xor", "adc", "sbb", "inc", "dec",
    "xadd", "cmpxchg", "not", "neg",
})


class StructFieldAccess(TypedDict, total=False):
    offset: str
    access_count: int
    reads: int
    writes: int
    sample_insn: str


class StructInferResult(TypedDict, total=False):
    function: str
    base_register: str
    fields: list[StructFieldAccess]
    error: str


def _decode_insn_at(ea: int) -> ida_ua.insn_t | None:
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, ea) == 0:
        return None
    return insn


def _next_head(ea: int, end_ea: int) -> int:
    return ida_bytes.next_head(ea, end_ea)


def _insn_mnem(insn: ida_ua.insn_t) -> str:
    try:
        return insn.get_canon_mnem().lower()
    except Exception:
        return ""


def _reg_name_matches(base_register: str, reg_name: str | None) -> bool:
    if not reg_name:
        return False
    return reg_name.strip().lower() == base_register.strip().lower()


def _mem_access_kind(insn: ida_ua.insn_t, op_idx: int) -> str | None:
    op_type = insn.ops[op_idx].type
    if op_type not in (ida_ua.o_mem, ida_ua.o_displ, ida_ua.o_phrase):
        return None
    mnem = _insn_mnem(insn)
    if mnem == "lea":
        return None
    if mnem in ("cmp", "test"):
        return "read"
    if op_idx == 0:
        if mnem in _RMW_MNEMS:
            return "read_write"
        return "write"
    if mnem == "xchg":
        return "read_write"
    return "read"


def _extract_base_disp_accesses(
    insn: ida_ua.insn_t,
    base_register: str,
) -> list[tuple[int, str]]:
    """Return (offset, access_kind) pairs for matching base+disp operands."""
    hits: list[tuple[int, str]] = []
    for i in range(8):
        if insn.ops[i].type == ida_ua.o_void:
            break
        op = insn.ops[i]
        if op.type == ida_ua.o_displ:
            base = idaapi.get_reg_name(op.reg) if op.reg else None
            if not _reg_name_matches(base_register, base):
                continue
            kind = _mem_access_kind(insn, i)
            if kind:
                hits.append((op.addr & 0xFFFFFFFFFFFFFFFF, kind))
        elif op.type == ida_ua.o_phrase:
            base = idaapi.get_reg_name(op.reg) if op.reg else None
            if not _reg_name_matches(base_register, base):
                continue
            kind = _mem_access_kind(insn, i)
            if kind:
                hits.append((op.addr & 0xFFFFFFFFFFFFFFFF, kind))
    return hits


def _infer_struct_fields(
    func_ea: int,
    base_register: str,
    limit: int,
) -> StructInferResult:
    func = idaapi.get_func(func_ea)
    if func is None:
        return {"error": f"No function at {hex(func_ea)}"}

    if limit <= 0 or limit > _STRUCT_INFER_MAX_FIELDS:
        limit = _STRUCT_INFER_MAX_FIELDS

    field_stats: dict[int, dict] = {}

    ea = func.start_ea
    while ea < func.end_ea:
        insn = _decode_insn_at(ea)
        if insn is None:
            ea = _next_head(ea, func.end_ea)
            if ea == idaapi.BADADDR:
                break
            continue

        insn_text = idc.GetDisasm(ea) or ""
        for offset, kind in _extract_base_disp_accesses(insn, base_register):
            stats = field_stats.setdefault(offset, {
                "access_count": 0,
                "reads": 0,
                "writes": 0,
                "sample_insn": insn_text,
            })
            stats["access_count"] += 1
            if kind in ("read", "read_write"):
                stats["reads"] += 1
            if kind in ("write", "read_write"):
                stats["writes"] += 1

        ea = _next_head(ea, func.end_ea)
        if ea == idaapi.BADADDR:
            break

    fields: list[StructFieldAccess] = []
    for offset in sorted(field_stats):
        stats = field_stats[offset]
        fields.append({
            "offset": hex(offset),
            "access_count": stats["access_count"],
            "reads": stats["reads"],
            "writes": stats["writes"],
            "sample_insn": stats["sample_insn"],
        })
        if len(fields) >= limit:
            break

    return {
        "function": hex(func.start_ea),
        "base_register": base_register.strip().lower(),
        "fields": fields,
    }


@tool
@idasync
@tool_timeout(120.0)
def struct_infer(
    addr: Annotated[str, "Function address or name"],
    base_register: Annotated[str, "Struct base register (default: rcx for x64 this)"] = "rcx",
    limit: Annotated[int, "Max fields returned (default: 200)"] = 200,
) -> StructInferResult:
    """Infer struct field offsets from [base+disp] memory access patterns.

    Scans a function for displacements off base_register (e.g. this=rcx)
    and aggregates read/write counts per offset. Does not apply types."""
    try:
        ea = parse_address(addr)
    except Exception as exc:
        return {"error": str(exc)}

    return _infer_struct_fields(ea, base_register, limit)


# ============================================================================
# list_enums — enumerate local enums (used by export_session)
# ============================================================================


@tool
@idasync
@tool_timeout(60.0)
def list_enums() -> list[dict]:
    """List all local enums with member names and values."""
    results: list[dict] = []
    try:
        qty = idc.get_enum_qty()
    except Exception:
        qty = 0

    for i in range(qty):
        try:
            enum_id = idc.getn_enum(i)
            if enum_id == idc.BADADDR:
                continue
            enum_name = idc.get_enum_name(enum_id) or f"enum_{enum_id}"
            members: list[dict] = []
            member_id = idc.get_first_enum_member(enum_id, 0)
            while member_id != idc.BADADDR:
                members.append({
                    "name": idc.get_enum_member_name(member_id) or "",
                    "value": idc.get_enum_member_value(member_id),
                })
                member_id = idc.get_next_enum_member(enum_id, member_id, 0)
            results.append({
                "name": enum_name,
                "member_count": len(members),
                "members": members,
            })
        except Exception:
            continue

    return results
