"""Resolution trace + Mermaid renderer.

A `Trace` is the recorded yield stream of a `resolve_steps` generator. The
async driver in `aiodns.resolver` calls `record(step)` on the trace for
every yielded effect, and asks for a `child(sname)` whenever a glueless
sub-resolution starts. `to_mermaid()` renders the recorded events as a
Mermaid `sequenceDiagram` with one lane per zone-cut visited; nested
sub-resolutions are appended below the parent diagram (Mermaid sequence
diagrams do not nest).

Trace stores opaque step objects and dispatches on `__class__.__name__`
so it never has to import the resolver module — keeping imports
unidirectional (`resolver -> trace`).
"""


class Trace:
    def __init__(self, sname=None):
        self.sname = sname
        self.events = []
        self.children = []

    def record(self, step):
        self.events.append(step)

    def child(self, sname=None):
        c = Trace(sname)
        self.children.append(c)
        return c

    def __repr__(self):
        return (
            f"<Trace sname={self.sname!r} events={len(self.events)} children={len(self.children)}>"
        )

    def to_mermaid(self):
        """Render this trace, and any sub-traces, as Mermaid sequence diagrams.

        Output is a ``sequenceDiagram`` per trace: the client is always
        participant ``C``, and each zone visited gets ``Z0``, ``Z1``, ... in the
        order first queried, which mirrors the descent a reader is trying to
        follow. Sub-traces (glueless address lookups) are appended as separate
        diagrams rather than nested, because Mermaid has no composition for that.
        """
        header = ["sequenceDiagram", "    participant C as client"]
        participants = {}
        body = []
        last_zone_id = ["C"]

        def participant_id(zone):
            key = str(zone) if zone is not None else "."
            if not key:
                key = "."
            if key not in participants:
                pid = f"Z{len(participants)}"
                participants[key] = pid
                header.append(f"    participant {pid} as {key}")
            return participants[key]

        title = ""
        if self.sname is not None:
            qname = getattr(self.sname, "qname", self.sname)
            qtype = getattr(self.sname, "qtype", None)
            qtype_name = getattr(qtype, "name", str(qtype)) if qtype is not None else ""
            title = f"    Note over C: resolve {qname} {qtype_name}"

        for ev in self.events:
            cn = ev.__class__.__name__
            if cn == "SendQuery":
                pid = participant_id(ev.entry.zone)
                qname = ev.questions[0].name if ev.questions else "?"
                qtype = ev.questions[0].qtype if ev.questions else None
                qtype_name = getattr(qtype, "name", str(qtype))
                body.append(f"    C->>{pid}: {qname} {qtype_name}")
                last_zone_id[0] = pid
            elif cn == "Referral":
                body.append(
                    f"    {last_zone_id[0]}-->>C: referral {ev.new_zone}"
                    f" (match {ev.match_before}->{ev.match_after})"
                )
            elif cn == "Answer":
                body.append(f"    {last_zone_id[0]}-->>C: AA, {len(ev.records)} records")
            elif cn == "Nodata":
                body.append(f"    Note over C: NODATA SOA={ev.soa.name if ev.soa else '?'}")
            elif cn == "Nxdomain":
                body.append("    Note over C: NXDOMAIN")
            elif cn == "Demote":
                ns = ev.entry.ns if ev.entry is not None else "?"
                body.append(f"    Note over C: demote {ns} ({ev.reason})")
            elif cn == "NeedAddress":
                body.append(f"    Note over C: glueless: resolve {ev.ns_name}")
            elif cn == "Cname":
                body.append(f"    Note over C: CNAME {ev.target}")
            elif cn == "Done":
                body.append("    Note over C: done")
            elif cn == "Fail":
                body.append(f"    Note over C: FAIL {ev.reason}")
                body.append(f"    Note over C: FAIL {ev.reason}")

        lines = list(header)
        if title:
            lines.append(title)
        lines.extend(body)
        out = "\n".join(lines)
        for child in self.children:
            out += "\n\n" + child.to_mermaid()
        return out
