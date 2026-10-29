def generate_hypotheses(df):
    """Produce transparent heuristic hypotheses, not definitive causal claims."""
    if df.empty:
        return [{
            "hypothesis": "No parsed events available",
            "evidence": "The input file did not contain supported log records.",
            "next_step": "Check the file format and parser's supported timestamp/severity pattern.",
            "confidence": "Low"
        }]
    text = " ".join(df["message"].astype(str).str.lower().tolist())
    levels = df["level"].astype(str).str.upper()
    hypotheses = []
    def add(name, evidence, next_step, confidence):
        hypotheses.append({"hypothesis": name, "evidence": evidence,
                           "next_step": next_step, "confidence": confidence})
    db_mask = df["message"].astype(str).str.contains(r"database|db |sql|connection pool", case=False, regex=True)
    api_mask = df["message"].astype(str).str.contains(r"http\s*5\d\d|request failed|api", case=False, regex=True)
    net_mask = df["message"].astype(str).str.contains(r"dns|network|connection reset|unreachable", case=False, regex=True)
    mem_mask = df["message"].astype(str).str.contains(r"memory|oom|out of memory", case=False, regex=True)
    if db_mask.any():
        first_db = df.loc[db_mask, "timestamp"].min()
        api_after = api_mask & (df["timestamp"] >= first_db) if df["timestamp"].notna().any() and str(first_db) != "NaT" else api_mask
        evidence = f"{int(db_mask.sum())} database-related event(s) found."
        if api_after.any():
            evidence += f" {int(api_after.sum())} API/server failure event(s) occur at or after the first database-related event."
        add("Database latency or connectivity issue", evidence,
            "Inspect database health, connection pool metrics, query latency, and matching request IDs.",
            "Medium" if api_after.any() else "Low")
    if net_mask.any():
        add("Network or name-resolution issue", f"{int(net_mask.sum())} network/DNS-related event(s) found.",
            "Check DNS lookup, routes, endpoint availability, and connection-reset details.", "Medium")
    if mem_mask.any():
        add("Memory or resource pressure", f"{int(mem_mask.sum())} memory/resource-related event(s) found.",
            "Compare memory/resource metrics with the incident timestamps and inspect container limits.", "Medium")
    if (levels.isin(["CRITICAL", "FATAL"])).any():
        add("Critical application event", f"{int(levels.isin(['CRITICAL','FATAL']).sum())} critical-level event(s) found.",
            "Inspect the full stack trace and events immediately before the first critical event.", "Medium")
    if not hypotheses:
        add("No specific root-cause pattern identified",
            "No database, network, memory, or critical-event pattern matched the available messages.",
            "Inspect unclassified events and add domain-specific rules for the application.", "Low")
    return hypotheses
