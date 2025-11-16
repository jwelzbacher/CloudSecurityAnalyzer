import { Badge } from "@/components/ui/badge";
import type { Status } from "@/lib/zodSchemas";

interface StatusChipsProps {
  selected: Status[];
  onChange: (selected: Status[]) => void;
}

const ALL_STATUSES: Status[] = ["PASS", "FAIL", "SKIP", "INFO"];

// Map Status → Badge variant name used by <Badge>
const STATUS_VARIANT_MAP: Record<
  Status,
  "pass" | "fail" | "skip" | "info"
> = {
  PASS: "pass",
  FAIL: "fail",
  SKIP: "skip",
  INFO: "info",
};

export function StatusChips({ selected, onChange }: StatusChipsProps) {
  const toggleStatus = (status: Status) => {
    if (selected.includes(status)) {
      onChange(selected.filter((s) => s !== status));
    } else {
      onChange([...selected, status]);
    }
  };

  return (
    <div className="flex flex-wrap gap-2">
      {ALL_STATUSES.map((status) => (
        <Badge
          key={status}
          variant={
            selected.includes(status) ? STATUS_VARIANT_MAP[status] : "outline"
          }
          className="cursor-pointer"
          onClick={() => toggleStatus(status)}
        >
          {status}
        </Badge>
      ))}
    </div>
  );
}
