"""
transcript_generator.py — Debate Transcript Formatter

Transforms raw debate data into a formatted, readable transcript
suitable for display in the Streamlit UI and console output.

    Raw Debate Data
        ↓
    Transcript Generator
        ↓
    Formatted Output
"""


class TranscriptGenerator:
    """Formats debate rounds into display-ready transcripts."""

    @staticmethod
    def format_console(debate_result):
        """Format debate for console output."""
        lines = []
        lines.append("=" * 60)
        lines.append("  AGENT DEBATE TRANSCRIPT")
        lines.append("=" * 60)

        for round_data in debate_result["rounds"]:
            lines.append("")
            lines.append(f"  ── Round {round_data['round']}: {round_data['title']} ──")
            lines.append("")

            for stmt in round_data["statements"]:
                agent = stmt["agent"]

                if round_data["round"] == 1:
                    lines.append(f"  {agent}:")
                    lines.append(f"    Position: {stmt['position']}")
                    lines.append(f"    Risk: {stmt['risk_level']}  |  Confidence: {stmt['confidence']}")
                    lines.append(f"    {stmt['argument']}")
                    lines.append("")

                elif round_data["round"] == 2:
                    responding = stmt.get("responding_to", "")
                    lines.append(f"  {agent} → {responding}:")
                    lines.append(f"    {stmt['argument']}")
                    lines.append("")

                elif round_data["round"] == 3:
                    lines.append(f"  {agent} (Final):")
                    lines.append(f"    {stmt['final_position']}")
                    lines.append("")

        lines.append("=" * 60)
        return "\n".join(lines)

    @staticmethod
    def format_streamlit(debate_result):
        """
        Format debate for Streamlit display.

        Returns a list of dicts for rendering in the UI.
        """
        formatted = []

        for round_data in debate_result["rounds"]:
            round_entries = {
                "round": round_data["round"],
                "title": round_data["title"],
                "entries": []
            }

            for stmt in round_data["statements"]:
                entry = {
                    "agent": stmt["agent"],
                    "round": round_data["round"],
                }

                if round_data["round"] == 1:
                    entry["type"] = "opening"
                    entry["content"] = stmt["argument"]
                    entry["position"] = stmt["position"]
                    entry["risk"] = stmt["risk_level"]
                    entry["confidence"] = stmt["confidence"]

                elif round_data["round"] == 2:
                    entry["type"] = "rebuttal"
                    entry["content"] = stmt["argument"]
                    entry["responding_to"] = stmt.get("responding_to", "")

                elif round_data["round"] == 3:
                    entry["type"] = "final"
                    entry["content"] = stmt["final_position"]

                round_entries["entries"].append(entry)

            formatted.append(round_entries)

        return formatted

    @staticmethod
    def format_timeline(debate_result):
        """
        Format debate as a timeline for the demo.

        Returns a flat list of events in chronological order.
        """
        timeline = []
        time_offset = 0

        for round_data in debate_result["rounds"]:
            for stmt in round_data["statements"]:
                timeline.append({
                    "time_offset": time_offset,
                    "round": round_data["round"],
                    "agent": stmt["agent"],
                    "event": _summarize_statement(stmt, round_data["round"]),
                })
                time_offset += 2  # seconds between events

        return timeline


def _summarize_statement(stmt, round_num):
    """Create a short summary of a statement for timeline display."""
    if round_num == 1:
        return f"Position: {stmt.get('position', 'N/A')} (Risk: {stmt.get('risk_level', 'N/A')})"
    elif round_num == 2:
        return f"Responds to {stmt.get('responding_to', 'N/A')}"
    elif round_num == 3:
        content = stmt.get("final_position", "")
        return content[:80] + "..." if len(content) > 80 else content
