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
        return "<Trace sname=%r events=%d children=%d>" % (
            self.sname,
            len(self.events),
            len(self.children),
        )

    def to_mermaid(self):
        header = ["sequenceDiagram", "    participant C as client"]
        participants = {}
        body = []
        last_zone_id = ["C"]

        def participant_id(zone):
            key = str(zone) if zone is not None else "."
            if not key:
                key = "."
            if key not in participants:
                pid = "Z%d" % len(participants)
                participants[key] = pid
                header.append("    participant %s as %s" % (pid, key))
            return participants[key]

        title = ""
        if self.sname is not None:
            qname = getattr(self.sname, "qname", self.sname)
            qtype = getattr(self.sname, "qtype", None)
            qtype_name = getattr(qtype, "name", str(qtype)) if qtype is not None else ""
            title = "    Note over C: resolve %s %s" % (qname, qtype_name)

        for ev in self.events:
            cn = ev.__class__.__name__
            if cn == "SendQuery":
                pid = participant_id(ev.entry.zone)
                qname = ev.questions[0].name if ev.questions else "?"
                qtype = ev.questions[0].qtype if ev.questions else None
                qtype_name = getattr(qtype, "name", str(qtype))
                body.append("    C->>%s: %s %s" % (pid, qname, qtype_name))
                last_zone_id[0] = pid
            elif cn == "Referral":
                body.append(
                    "    %s-->>C: referral %s (match %d->%d)"
                    % (
                        last_zone_id[0],
                        ev.new_zone,
                        ev.match_before,
                        ev.match_after,
                    )
                )
            elif cn == "Answer":
                body.append("    %s-->>C: AA, %d records" % (last_zone_id[0], len(ev.records)))
            elif cn == "Nodata":
                body.append("    Note over C: NODATA SOA=%s" % (ev.soa.name if ev.soa else "?"))
            elif cn == "Nxdomain":
                body.append("    Note over C: NXDOMAIN")
            elif cn == "Demote":
                ns = ev.entry.ns if ev.entry is not None else "?"
                body.append("    Note over C: demote %s (%s)" % (ns, ev.reason))
            elif cn == "NeedAddress":
                body.append("    Note over C: glueless: resolve %s" % ev.ns_name)
            elif cn == "Cname":
                body.append("    Note over C: CNAME %s" % ev.target)
            elif cn == "Done":
                body.append("    Note over C: done")
            elif cn == "Fail":
                body.append("    Note over C: FAIL %s" % ev.reason)

        lines = list(header)
        if title:
            lines.append(title)
        lines.extend(body)
        out = "\n".join(lines)
        for child in self.children:
            out += "\n\n" + child.to_mermaid()
        return out
