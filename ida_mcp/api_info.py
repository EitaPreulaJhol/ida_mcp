"""Binary metadata tools — architecture, compiler, hashes, and analysis status.

Tools ported from idamcp-extendedtools api_info.py and api_core.py,
adapted for direct in-process IDA SDK access.
"""

import json
import os

import ida_auto
import ida_entry
import ida_ida
import ida_kernwin
import ida_loader
import ida_nalt
import ida_problems
import ida_typeinf
import idaapi
import idc
import idautils

from .rpc import tool
from .sync import idasync
from .compat import get_entry_qty, get_entry_ordinal, get_entry, get_entry_name


# ===========================================================================
# Tools
# ===========================================================================


@tool
@idasync
def get_binary_info() -> str:
    """Get comprehensive binary file information.

    Returns file path, input file path, base address, processor, bitness, and
    compiler info.
    """
    ida_auto.auto_wait()
    info: dict = {
        "input_file_path": ida_nalt.get_input_file_path(),
        "input_file_name": os.path.basename(ida_nalt.get_input_file_path()) if ida_nalt.get_input_file_path() else None,
        "image_base": hex(ida_nalt.get_imagebase()),
        "processor": idc.get_processor_name(),
        "bitness": 64 if idaapi.inf_is_64bit() else 32,
        "is_64bit": idaapi.inf_is_64bit(),
        "is_32bit": not idaapi.inf_is_64bit(),
        "min_ea": hex(ida_ida.inf_get_min_ea()),
        "max_ea": hex(ida_ida.inf_get_max_ea()),
        "image_size": ida_ida.inf_get_max_ea() - ida_ida.inf_get_min_ea(),
    }

    # Compiler info
    try:
        cc = ida_ida.compiler_info_t()
        ida_ida.inf_get_cc(cc)
        info["compiler"] = ida_typeinf.get_compiler_name(cc.id)
    except Exception:
        info["compiler"] = None

    # File hashes
    try:
        md5 = ida_nalt.retrieve_input_file_md5()
        if md5:
            info["md5"] = md5.hex()
    except Exception:
        info["md5"] = None

    try:
        sha256 = ida_nalt.retrieve_input_file_sha256()
        if sha256:
            info["sha256"] = sha256.hex()
    except Exception:
        info["sha256"] = None

    return json.dumps(info, indent=2)


def _get_architecture_info_impl() -> str:
    """Plain (non-synced) arch logic — shared with get_processor_info."""
    return json.dumps({
        "processor": idc.get_processor_name(),
        "bitness": 64 if idaapi.inf_is_64bit() else 32,
        "is_64bit": idaapi.inf_is_64bit(),
        "is_32bit": not idaapi.inf_is_64bit(),
    }, indent=2)


@tool
@idasync
def get_architecture_info() -> str:
    """Get processor/architecture information."""
    ida_auto.auto_wait()
    return _get_architecture_info_impl()


@tool
@idasync
def get_compiler_info() -> str:
    """Get compiler and ABI information."""
    ida_auto.auto_wait()
    try:
        cc = ida_ida.compiler_info_t()
        ida_ida.inf_get_cc(cc)
        return json.dumps({
            "compiler": ida_typeinf.get_compiler_name(cc.id),
            "abi": ida_typeinf.get_abi_name(),
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


@tool
@idasync
def get_hexrays_version() -> str:
    """Check if Hex-Rays decompiler is available and get its version."""
    ida_auto.auto_wait()
    try:
        import ida_hexrays
        if ida_hexrays.init_hexrays_plugin():
            version = ida_hexrays.get_hexrays_version()
            return json.dumps({"hexrays_available": True, "version": version})
        else:
            return json.dumps({"hexrays_available": False})
    except Exception:
        return json.dumps({"hexrays_available": False})


@tool
@idasync
def get_processor_info() -> str:
    """Get processor type and features."""
    return _get_architecture_info_impl()


@tool
@idasync
def get_problems() -> str:
    """Get analysis problems/warnings from the database."""
    ida_auto.auto_wait()
    problem_types = {
        ida_problems.PR_NOBASE: "PR_NOBASE",
        ida_problems.PR_NONAME: "PR_NONAME",
        ida_problems.PR_NOFOP: "PR_NOFOP",
        ida_problems.PR_NOCMT: "PR_NOCMT",
        ida_problems.PR_NOXREFS: "PR_NOXREFS",
        ida_problems.PR_JUMP: "PR_JUMP",
        ida_problems.PR_DISASM: "PR_DISASM",
        ida_problems.PR_HEAD: "PR_HEAD",
        ida_problems.PR_ILLADDR: "PR_ILLADDR",
        ida_problems.PR_MANYLINES: "PR_MANYLINES",
        ida_problems.PR_BADSTACK: "PR_BADSTACK",
        ida_problems.PR_ATTN: "PR_ATTN",
        ida_problems.PR_FINAL: "PR_FINAL",
        ida_problems.PR_ROLLED: "PR_ROLLED",
        ida_problems.PR_COLLISION: "PR_COLLISION",
        ida_problems.PR_DECIMP: "PR_DECIMP",
    }

    results: list[dict] = []
    for ptype, pname in problem_types.items():
        try:
            ea = ida_problems.get_problem(ptype, idaapi.BADADDR)
            while ea != idaapi.BADADDR:
                results.append({"address": hex(ea), "type": pname})
                ea = ida_problems.get_problem(ptype, ea + 1)
                if len(results) >= 2000:
                    break
        except Exception:
            pass
        if len(results) >= 2000:
            break

    return json.dumps({"problems": results, "count": len(results)}, indent=2)


@tool
@idasync
def get_image_size() -> str:
    """Get the image size (max_ea - min_ea) of the binary."""
    ida_auto.auto_wait()
    omin = ida_ida.inf_get_omin_ea()
    omax = ida_ida.inf_get_omax_ea()
    size = omax - omin
    return json.dumps({"min_ea": hex(omin), "max_ea": hex(omax), "image_size": size})


@tool
@idasync
def get_current_binary_name() -> str:
    """Get the base name of the currently loaded binary."""
    ida_auto.auto_wait()
    path = ida_nalt.get_input_file_path()
    name = os.path.basename(path) if path else None
    return json.dumps({"name": name})


@tool
@idasync
def get_base_address() -> str:
    """Get the base address of the binary."""
    ida_auto.auto_wait()
    return json.dumps({"base_address": hex(ida_nalt.get_imagebase())})


@tool
@idasync
def get_input_file_path() -> str:
    """Get the full path to the input file."""
    ida_auto.auto_wait()
    return json.dumps({"path": ida_nalt.get_input_file_path()})


@tool
@idasync
def get_input_file_md5() -> str:
    """Get the MD5 hash of the input file."""
    ida_auto.auto_wait()
    try:
        md5 = ida_nalt.retrieve_input_file_md5()
        return json.dumps({"md5": md5.hex() if md5 else None})
    except Exception:
        return json.dumps({"md5": None})


@tool
@idasync
def get_input_file_sha256() -> str:
    """Get the SHA256 hash of the input file."""
    ida_auto.auto_wait()
    try:
        sha256 = ida_nalt.retrieve_input_file_sha256()
        return json.dumps({"sha256": sha256.hex() if sha256 else None})
    except Exception:
        return json.dumps({"sha256": None})


@tool
@idasync
def get_analysis_status() -> str:
    """Get the current analysis status (auto-enabled, complete)."""
    ida_auto.auto_wait()
    return json.dumps({
        "is_auto_enabled": ida_auto.is_auto_enabled(),
        "is_analysis_complete": ida_auto.auto_is_ok(),
    })


@tool
@idasync
def wait_for_analysis() -> str:
    """Wait for auto-analysis to complete and return status."""
    ida_auto.auto_wait()
    return json.dumps({"ok": True, "is_analysis_complete": ida_auto.auto_is_ok()})


@tool
@idasync
def get_version_info() -> str:
    """Get IDA Pro kernel version information."""
    ida_auto.auto_wait()
    return json.dumps({"kernel_version": idaapi.get_kernel_version()})


@tool
@idasync
def idb_save(path: str = "") -> str:
    """Save the active IDB to disk, optionally to a new path.

    In GUI mode uses IDA's native in-place save (equivalent to Ctrl+W) and
    never packs/kills the live working files; for an explicit different
    destination writes a compressed snapshot copy. Ported from ida-pro-mcp.
    """
    ida_auto.auto_wait()
    try:
        save_path = path.strip() if path else ""
        if not save_path:
            save_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
        if not save_path:
            return json.dumps({"ok": False, "path": None,
                               "error": "Could not resolve IDB path"})
        try:
            is_gui = bool(ida_kernwin.is_idaq()) if hasattr(ida_kernwin, "is_idaq") else False
        except Exception:
            is_gui = False
        if is_gui:
            current = ida_loader.get_path(ida_loader.PATH_TYPE_IDB)
            if path and save_path != current:
                ok = bool(ida_loader.save_database(save_path, ida_loader.DBFL_COMP))
            else:
                ok = bool(ida_loader.save_database(None, 0))
        else:
            flags = ida_loader.DBFL_KILL | ida_loader.DBFL_COMP
            ok = bool(ida_loader.save_database(save_path, flags))
        result: dict = {"ok": ok, "path": save_path}
        if not ok:
            result["error"] = "save_database returned false"
        return json.dumps(result)
    except Exception as e:
        return json.dumps({"ok": False, "path": None, "error": str(e)})


@tool
@idasync
def idb_meta() -> str:
    """Get IDB metadata: paths, file size on disk, root filename, IDA version."""
    ida_auto.auto_wait()
    try:
        idb_path = ida_loader.get_path(ida_loader.PATH_TYPE_IDB) or None
    except Exception:
        idb_path = None
    size = None
    if idb_path:
        try:
            size = os.path.getsize(idb_path)
        except OSError:
            size = None
    try:
        root = ida_nalt.get_root_filename() or None
    except Exception:
        root = None
    try:
        kernel = idaapi.get_kernel_version()
    except Exception:
        kernel = None
    return json.dumps({"idb_path": idb_path, "idb_size": size,
                       "root_filename": root, "kernel_version": kernel})


@tool
@idasync
def get_analysis_prompt() -> str:
    """Get a Markdown briefing to bootstrap an analysis session.

    Compact orientation snapshot (binary, arch, scale, segments, entries,
    imports/strings counts) meant to be pasted into an agent prompt.
    Ported from idamcp-extendedtools.
    """
    ida_auto.auto_wait()
    try:
        module = ida_nalt.get_root_filename() or "<unknown>"
    except Exception:
        module = "<unknown>"
    try:
        proc = idc.get_processor_name() or "<unknown>"
    except Exception:
        proc = "<unknown>"
    try:
        bits = 64 if idaapi.inf_is_64bit() else 32
    except Exception:
        bits = "?"
    try:
        base = hex(idaapi.get_imagebase())
    except Exception:
        base = "?"
    try:
        nfuncs = sum(1 for _ in idautils.Functions())
    except Exception:
        nfuncs = "?"
    try:
        import ida_segment
        segs = []
        for seg_ea in idautils.Segments():
            try:
                seg = idaapi.getseg(seg_ea)
                segs.append(ida_segment.get_segm_name(seg) or hex(seg_ea))
            except Exception:
                continue
    except Exception:
        segs = []
    try:
        entries = []
        for i in range(get_entry_qty()):
            ordinal = get_entry_ordinal(i)
            entries.append(f"{get_entry_name(ordinal) or '?'} @ {hex(get_entry(ordinal))}")
    except Exception:
        entries = []
    try:
        nimps = ida_nalt.get_import_module_qty()
    except Exception:
        nimps = "?"
    try:
        nstrings = sum(1 for _ in idautils.Strings())
    except Exception:
        nstrings = "?"
    prompt = (
        f"# Analysis target: {module}\n\n"
        f"- Processor: {proc} ({bits}-bit), image base {base}\n"
        f"- Scale: {nfuncs} functions, {nstrings} strings, {nimps} import modules\n"
        f"- Segments: {', '.join(segs) if segs else '(none)'}\n"
        f"- Entry points: {'; '.join(entries) if entries else '(none)'}\n\n"
        f"Suggested first calls: `survey_binary()` for triage, then "
        f"`analyze_function()` on entries of interest."
    )
    return json.dumps({"prompt": prompt})
