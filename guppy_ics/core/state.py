import uuid
from typing import Dict, Any, Optional


class AnalysisState:
    """
    Central in-memory state for a Guppy ICS analysis run.
    Protocol plugins write here; persistence happens later.
    """

    def __init__(self):
        # asset_id -> asset dict
        self.assets: Dict[str, Dict[str, Any]] = {}

        # identifier (IP, MAC, etc.) -> asset_id
        self.asset_index: Dict[str, str] = {}

        # (src_id, dst_id, protocol, function) -> comm dict
        self.communications: Dict[tuple, Dict[str, Any]] = {}

        # optional protocol-level events
        self.events = []

    # -------------------------
    # Asset handling
    # -------------------------

    def register_asset(
        self,
        identifier: str,
        *,
        role: Optional[str] = None,
        protocol: Optional[str] = None,
        vendor: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        if identifier in self.asset_index:
            asset_id = self.asset_index[identifier]
            asset = self.assets[asset_id]
        else:
            asset_id = str(uuid.uuid4())
            id_type = self._infer_identifier_type(identifier)
            asset = {
                "asset_id": asset_id,
                # primary identifier (legacy-compatible)
                "identifier": identifier,
                "identifier_type": id_type,
                # multi-identifier store
                "identifiers": {
                    id_type: {identifier}
                },
                "role": None,
                "vendor": None,
                "protocols": set(),
                "metadata": {},
            }
            self.assets[asset_id] = asset
            self.asset_index[identifier] = asset_id

        # Ensure identifiers structure exists (for legacy assets)
        if "identifiers" not in asset:
            asset["identifiers"] = {
                asset.get("identifier_type", "unknown"): {asset.get("identifier")}
            }

        # Normalize identifier
        id_type = self._infer_identifier_type(identifier)
        asset["identifiers"].setdefault(id_type, set()).add(identifier)
        self.asset_index[identifier] = asset_id

        if role:
            asset["role"] = asset["role"] or role

        if vendor:
            asset["vendor"] = asset["vendor"] or vendor

        if protocol:
            asset["protocols"].add(protocol)

        if metadata:
            asset["metadata"].update(metadata)

        return asset_id

    # -------------------------
    # Communication handling
    # -------------------------

    def register_communication(
        self,
        *,
        src: str,
        dst: str,
        protocol: str,
        function: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        src_id = self.asset_index.get(src) or self.register_asset(src, protocol=protocol)
        dst_id = self.asset_index.get(dst) or self.register_asset(dst, protocol=protocol)

        key = (src_id, dst_id, protocol, function)

        if key not in self.communications:
            self.communications[key] = {
                "src_asset_id": src_id,
                "dst_asset_id": dst_id,
                "protocol": protocol,
                "function": function,
                "count": 0,
                "metadata": {},
            }

        comm = self.communications[key]
        comm["count"] += 1

        if metadata:
            comm["metadata"].update(metadata)

    # Backward compatibility helper
    def register_communication_ip_compat(self, **kwargs):
        return self.register_communication(
            src=kwargs["src_ip"],
            dst=kwargs["dst_ip"],
            protocol=kwargs["protocol"],
            function=kwargs.get("function"),
            metadata=kwargs.get("metadata"),
        )

    # -------------------------
    # Identity linking
    # -------------------------

    def link_identifiers(
        self,
        a: str,
        b: str,
        *,
        protocol: Optional[str] = None,
        reason: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        a_id = self.asset_index.get(a) or self.register_asset(a, protocol=protocol)
        b_id = self.asset_index.get(b) or self.register_asset(b, protocol=protocol)

        if a_id == b_id:
            return a_id

        a_type = self._infer_identifier_type(a)
        b_type = self._infer_identifier_type(b)

        # Prefer MAC as canonical anchor
        keep_id, drop_id = a_id, b_id
        if b_type == "mac" and a_type != "mac":
            keep_id, drop_id = b_id, a_id

        canonical_id = self._merge_assets(keep_id, drop_id)

        asset = self.assets[canonical_id]

        if reason:
            links = asset["metadata"].setdefault("identity_links", set())
            links.add((a, b, reason))

        if metadata:
            asset["metadata"].update(metadata)

        if protocol:
            asset["protocols"].add(protocol)

        return canonical_id

    def _merge_assets(self, keep_id: str, drop_id: str) -> str:
        if keep_id == drop_id:
            return keep_id

        keep = self.assets[keep_id]
        drop = self.assets[drop_id]

        # Merge identifiers
        for t, vals in drop.get("identifiers", {}).items():
            keep["identifiers"].setdefault(t, set()).update(vals)

        # Merge protocols
        keep["protocols"].update(drop.get("protocols", set()))

        # Merge metadata
        keep["metadata"].update(drop.get("metadata", {}))

        # Preserve role/vendor if already set
        if not keep.get("role") and drop.get("role"):
            keep["role"] = drop["role"]
        if not keep.get("vendor") and drop.get("vendor"):
            keep["vendor"] = drop["vendor"]

        # Rewrite asset_index
        for vals in keep["identifiers"].values():
            for ident in vals:
                self.asset_index[ident] = keep_id

        # Rewrite communications
        new_comms: Dict[tuple, Dict[str, Any]] = {}
        for (src, dst, proto, func), comm in self.communications.items():
            new_src = keep_id if src == drop_id else src
            new_dst = keep_id if dst == drop_id else dst
            key = (new_src, new_dst, proto, func)

            if key not in new_comms:
                comm["src_asset_id"] = new_src
                comm["dst_asset_id"] = new_dst
                new_comms[key] = comm
            else:
                new_comms[key]["count"] += comm["count"]
                new_comms[key]["metadata"].update(comm.get("metadata", {}))

        self.communications = new_comms

        del self.assets[drop_id]
        return keep_id

    # -------------------------
    # Events (optional)
    # -------------------------

    def register_event(
        self,
        *,
        protocol: str,
        event_type: str,
        src_ip: str,
        dst_ip: str,
        details: Dict[str, Any],
    ) -> None:
        self.events.append({
            "protocol": protocol,
            "event_type": event_type,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "details": details,
        })

    # -------------------------
    # Introspection helpers
    # -------------------------

    def summary(self) -> Dict[str, int]:
        return {
            "assets": len(self.assets),
            "communications": len(self.communications),
            "events": len(self.events),
        }

    def _infer_identifier_type(self, identifier: str) -> str:
        if ":" in identifier and len(identifier.split(":")) == 6:
            return "mac"
        if "." in identifier:
            return "ip"
        return "unknown"

    def infer_profinet_roles(self) -> None:
        """
        Infer PROFINET controller / device roles from RTC1 traffic.
        """

        outgoing = {}
        incoming = {}

        for comm in self.communications.values():
            if comm["protocol"] != "profinet":
                continue
            if comm.get("function") != "rtc1_io":
                continue

            src = comm["src_asset_id"]
            dst = comm["dst_asset_id"]
            count = comm.get("count", 1)

            outgoing[src] = outgoing.get(src, 0) + count
            incoming[dst] = incoming.get(dst, 0) + count

        for asset_id, asset in self.assets.items():
            out_c = outgoing.get(asset_id, 0)
            in_c = incoming.get(asset_id, 0)

            if out_c > in_c:
                asset["role"] = asset.get("role") or "profinet_controller"
            elif in_c > out_c:
                asset["role"] = asset.get("role") or "profinet_device"
