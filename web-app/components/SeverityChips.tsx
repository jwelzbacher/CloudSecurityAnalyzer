"use client";

import { Severity } from "@/lib/zodSchemas";
import { Badge } from "./ui/badge";
import { cn } from "@/lib/utils";

interface SeverityChipsProps {
  selected: Severity[];
  onChange: (severities: Severity[]) => void;
  className?: string;
}

const allSeverities: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
];

const severityLabels: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Info",
};

export function SeverityChips({
  selected,
  onChange,
  className,
}: SeverityChipsProps) {
  const toggleSeverity = (severity: Severity) => {
    if (selected.includes(severity)) {
      onChange(selected.filter((s) => s !== severity));
    } else {
      onChange([...selected, severity]);
    }
  };

  return (
    <div className={cn("flex flex-wrap gap-2", className)}>
      {allSeverities.map((severity) => (
        <Badge
          key={severity}
          variant={selected.includes(severity) ? severity : "outline"}
          className="cursor-pointer"
          onClick={() => toggleSeverity(severity)}
        >
          {severityLabels[severity]}
        </Badge>
      ))}
    </div>
  );
}

