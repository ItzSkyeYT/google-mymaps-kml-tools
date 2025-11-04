import csv
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from xml.etree.ElementTree import Element, SubElement, ElementTree

Point = Dict[str, Any]
DEFAULT_MAX_PER_FILE = 2000


def prompt_input_path() -> Path:
    while True:
        try:
            value = input("Enter path to CSV/JSON: ").strip().strip('"')
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            raise SystemExit(1)
        if not value:
            print("Please enter a value.")
            continue
        path = Path(value).expanduser().resolve()
        if not path.is_file():
            print(f"Input file not found: {path}")
            continue
        return path


def prompt_output_dir(input_path: Path) -> Path:
    try:
        value = input("Output directory (leave blank for default): ").strip().strip('"')
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        raise SystemExit(1)
    base_dir = Path(value).expanduser().resolve() if value else input_path.parent
    base_dir.mkdir(parents=True, exist_ok=True)
    output_dir = base_dir / f"{input_path.stem}_kml"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def prompt_int(prompt_text: str, default: int) -> int:
    try:
        raw = input(prompt_text).strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        raise SystemExit(1)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        print("Invalid number, using default.")
        return default
    return value if value > 0 else default


def load_points(path: Path) -> List[Point]:
    suffix = path.suffix.lower()
    if suffix == ".csv":
        return list(_load_from_csv(path))
    if suffix == ".json":
        return list(_load_from_json(path))
    raise ValueError(f"Unsupported input format: {suffix}")


def _load_from_csv(path: Path) -> Iterable[Point]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            yield _normalize_row(row)


def _load_from_json(path: Path) -> Iterable[Point]:
    with path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, list):
        raise ValueError("JSON must contain a list of point objects")
    for item in data:
        if isinstance(item, dict):
            yield _normalize_row(item)


def _to_float(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    return float(str(value))


def _to_int(value: Any) -> int:
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return 0


def _ensure_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value:
        try:
            maybe = json.loads(value)
            if isinstance(maybe, dict):
                return maybe
        except json.JSONDecodeError:
            pass
    return {}


def _normalize_row(raw: Dict[str, Any]) -> Point:
    lat = raw.get("lat")
    lon = raw.get("lon")
    if lat is None or lon is None:
        raise ValueError("Each row must include 'lat' and 'lon' values")

    description_html = raw.get("description_html") or raw.get("description")
    description_text = raw.get("description_text") or ""

    point: Point = {
        "map_mid": str(raw.get("map_mid", "")),
        "map_name": str(raw.get("map_name", "")),
        "layer_id": str(raw.get("layer_id", "")),
        "layer": str(raw.get("layer", "")).strip(),
        "layer_index": _to_int(raw.get("layer_index", 0)),
        "style_id": str(raw.get("style_id", "")),
        "style": str(raw.get("style", "")).strip(),
        "style_index": _to_int(raw.get("style_index", 0)),
        "icon_url": str(raw.get("icon_url", "")),
        "feature_id": str(raw.get("feature_id", "")),
        "feature_index": _to_int(raw.get("feature_index", 0)),
        "name": str(raw.get("name", "")).strip() or "Untitled",
        "description_html": description_html if isinstance(description_html, str) else str(description_html or ""),
        "description_text": str(description_text),
        "link": str(raw.get("link", "")),
        "type": str(raw.get("type", "")),
        "further_reading": str(raw.get("further_reading", "")),
        "contributor": str(raw.get("contributor", "")),
        "lat": _to_float(lat),
        "lon": _to_float(lon),
        "folder_path": str(raw.get("folder_path", "")),
        "extra_fields": _ensure_dict(raw.get("extra_fields", {})),
    }

    if not point["description_html"] and point["description_text"]:
        point["description_html"] = point["description_text"]

    return point


def sort_points(points: List[Point]) -> List[Point]:
    return sorted(points, key=lambda p: (p["layer_index"], p["style_index"], p["feature_index"]))


def sanitize_style_id(raw_id: str, fallback: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_-]", "_", raw_id or fallback)
    if not candidate:
        candidate = fallback or "style"
    if not candidate[0].isalpha():
        candidate = f"s_{candidate}"
    return candidate


def ensure_style(document: Element, registry: Dict[str, Element], style_id: str, icon_url: str) -> str:
    if not icon_url:
        return ""
    if style_id in registry:
        return style_id
    style_el = SubElement(document, "Style", attrib={"id": style_id})
    icon_style = SubElement(style_el, "IconStyle")
    icon = SubElement(icon_style, "Icon")
    href = SubElement(icon, "href")
    href.text = icon_url
    registry[style_id] = style_el
    return style_id


def build_description(point: Point) -> str:
    html = point.get("description_html", "")
    if html:
        return html

    fragments: List[str] = []
    if point.get("description_text"):
        fragments.append(point["description_text"])

    meta_lines: List[str] = []
    for label, key in (
        ("Layer", "layer"),
        ("Category", "style"),
        ("Type", "type"),
        ("Link", "link"),
        ("Further reading", "further_reading"),
        ("Contributor", "contributor"),
    ):
        value = point.get(key)
        if value:
            meta_lines.append(f"<b>{label}</b>: {value}")

    extra = point.get("extra_fields") or {}
    for key, value in extra.items():
        if key in {"X", "Y"}:
            continue
        if value:
            meta_lines.append(f"<b>{key}</b>: {value}")

    if meta_lines:
        fragments.append("<br/>".join(meta_lines))

    return "<br/>".join(fragments)


def add_extended_data(placemark: Element, point: Point) -> None:
    extended = SubElement(placemark, "ExtendedData")

    def _stringify(value: Any) -> Optional[str]:
        if value is None:
            return None
        if isinstance(value, str):
            return value if value else None
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return str(value)
        if isinstance(value, (list, dict)):
            return json.dumps(value, ensure_ascii=False, sort_keys=True)
        return str(value)

    def _add(name: str, value: Any) -> None:
        text_value = _stringify(value)
        if text_value is None or text_value == "":
            return
        data_el = SubElement(extended, "Data", name=name)
        SubElement(data_el, "value").text = text_value

    _add("layer", point.get("layer", ""))
    _add("style", point.get("style", ""))
    _add("type", point.get("type", ""))
    _add("link", point.get("link", ""))
    _add("further_reading", point.get("further_reading", ""))
    _add("contributor", point.get("contributor", ""))
    for key, value in (point.get("extra_fields") or {}).items():
        _add(key, value)


def build_flat_kml(points: List[Point], part_label: str) -> Element:
    kml = Element("kml", attrib={"xmlns": "http://www.opengis.net/kml/2.2"})
    document = SubElement(kml, "Document")

    folder = SubElement(document, "Folder")
    SubElement(folder, "name").text = part_label

    style_registry: Dict[str, Element] = {}
    style_id_map: Dict[Tuple[str, str], str] = {}
    counter = 1

    for point in points:
        key = (point.get("style_id", ""), point.get("icon_url", ""))
        if key not in style_id_map:
            raw_id = key[0] or f"style_{counter}"
            candidate = sanitize_style_id(raw_id, f"style_{counter}")
            if candidate in style_registry:
                candidate = f"{candidate}_{counter}"
            ensure_style(document, style_registry, candidate, key[1])
            style_id_map[key] = candidate if key[1] else ""
            counter += 1

        placemark = SubElement(folder, "Placemark")
        SubElement(placemark, "name").text = point.get("name") or "Untitled"

        description = build_description(point)
        if description:
            SubElement(placemark, "description").text = description

        style_ref = style_id_map.get(key, "")
        if style_ref:
            SubElement(placemark, "styleUrl").text = f"#{style_ref}"

        add_extended_data(placemark, point)

        point_el = SubElement(placemark, "Point")
        coord_el = SubElement(point_el, "coordinates")
        coord_el.text = f"{point['lon']},{point['lat']},0"

    return kml


def write_kml(root: Element, output_path: Path) -> None:
    tree = ElementTree(root)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)


def split_for_files(points: List[Point], cap: int) -> Iterable[List[Point]]:
    if cap <= 0 or len(points) <= cap:
        yield points
        return
    for index in range(0, len(points), cap):
        yield points[index:index + cap]


def resolve_output_dir(input_path: Path, output_dir: Path) -> Tuple[Path, str]:
    base_stem = input_path.stem
    return output_dir, base_stem


def main() -> None:
    input_path = prompt_input_path()
    output_dir = prompt_output_dir(input_path)
    max_per_file = prompt_int(f"Max placemarks per output file [{DEFAULT_MAX_PER_FILE}]: ", DEFAULT_MAX_PER_FILE)

    points = load_points(input_path)
    if not points:
        raise SystemExit("No points found in the input file")

    sorted_points = sort_points(points)
    file_chunks = list(split_for_files(sorted_points, max_per_file))
    num_files = len(file_chunks)
    padding = max(2, len(str(num_files)))

    written = 0
    for idx, chunk in enumerate(file_chunks, 1):
        part_label = f"{input_path.stem} part {idx}/{num_files}"
        root = build_flat_kml(chunk, part_label)
        filename = f"{input_path.stem}_part{idx:0{padding}d}.kml"
        destination = output_dir / filename
        write_kml(root, destination)
        written += len(chunk)
        print(f"  - part {idx}/{num_files}: {len(chunk)} placemarks -> {destination}")

    print(f"[ok] Wrote {written} placemarks split across {num_files} file(s) in {output_dir}")


if __name__ == "__main__":
    main()
