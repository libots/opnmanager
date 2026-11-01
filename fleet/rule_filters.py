def split(value): return set(v.strip() for v in value.split(",") if v.strip())


def filter_rows(rows, params, group_members=None):
    group_members = group_members or {}
    def matches(row):
        bindings = split(row.get("interface", ""))
        placement = "floating" if len(bindings) != 1 else ("group" if next(iter(bindings)) in group_members else "interface")
        if params.get("placement") and params["placement"] != placement: return False
        interface = params.get("interface")
        if interface and bindings:
            affected = interface in bindings or any(interface in group_members.get(b, set()) for b in bindings)
            if row.get("interfacenot", "0") == "1": affected = not affected
            if not affected: return False
        if params.get("category") and params["category"] not in split(row.get("categories", "")): return False
        if params.get("enabled") in ("0", "1") and row.get("enabled", "1") != params["enabled"]: return False
        if params.get("q") and params["q"].casefold() not in " ".join(str(v) for v in row.values()).casefold(): return False
        return True
    return [row for row in rows if matches(row)]
