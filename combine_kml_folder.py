import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Set
from xml.etree import ElementTree as ET
from zipfile import ZipFile

DEFAULT_MAX_PER_FILE = 2000
KML_NS = "http://www.opengis.net/kml/2.2"
PLACEMARK_TAG = f"{{{KML_NS}}}Placemark"
STYLE_TAG = f"{{{KML_NS}}}Style"
STYLE_MAP_TAG = f"{{{KML_NS}}}StyleMap"
STYLE_URL_TAG = f"{{{KML_NS}}}styleUrl"
DOCUMENT_TAG = f"{{{KML_NS}}}Document"
FOLDER_TAG = f"{{{KML_NS}}}Folder"
NAME_TAG = f"{{{KML_NS}}}name"
EXTENDED_DATA_TAG = f"{{{KML_NS}}}ExtendedData"
DATA_TAG = f"{{{KML_NS}}}Data"
VALUE_TAG = f"{{{KML_NS}}}value"

ET.register_namespace("", KML_NS)


@dataclass
class PlacemarkEntry:
    element: ET.Element
    source: str


def prompt_directory() -> Path:
    while True:
        try:
            value = input("Enter folder containing KML/KMZ files: ").strip().strip('"')
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            raise SystemExit(1)
        if not value:
            print("Please enter a path.")
            continue
        path = Path(value).expanduser().resolve()
        if not path.is_dir():
            print(f"Directory not found: {path}")
            continue
        return path


def prompt_output_dir(source_dir: Path) -> Path:
    try:
        value = input("Output directory (leave blank for default): ").strip().strip('"')
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        raise SystemExit(1)
    base_dir = Path(value).expanduser().resolve() if value else source_dir
    base_dir.mkdir(parents=True, exist_ok=True)
    output_dir = base_dir / f"{source_dir.name}_combined"
    output_dir.mkdir(parents=True, exist_ok=True)
    return output_dir


def prompt_basename(default: str) -> str:
    try:
        value = input(f"Base name for combined files [{default}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        raise SystemExit(1)
    return value or default


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


def load_kml_root(path: Path) -> ET.Element:
    suffix = path.suffix.lower()
    if suffix == ".kmz":
        with ZipFile(path) as archive:
            for name in sorted(archive.namelist()):
                if name.lower().endswith(".kml"):
                    data = archive.read(name)
                    return ET.fromstring(data)
        raise ValueError("KMZ archive does not contain a KML file.")
    if suffix == ".kml":
        return ET.parse(path).getroot()
    raise ValueError("Unsupported file type; expected .kml or .kmz.")


def iter_documents(root: ET.Element):
    if root.tag == DOCUMENT_TAG:
        yield root
    docs = root.findall(f".//{DOCUMENT_TAG}")
    if docs:
        for node in docs:
            yield node
    elif root.tag != DOCUMENT_TAG:
        yield root


def extract_style_elements(root: ET.Element) -> List[ET.Element]:
    styles: List[ET.Element] = []
    for document in iter_documents(root):
        for child in list(document):
            if child.tag in {STYLE_TAG, STYLE_MAP_TAG}:
                styles.append(child)
    return styles


def collect_placemarks(root: ET.Element) -> List[ET.Element]:
    placemarks: List[ET.Element] = []

    def walk(node: ET.Element) -> None:
        if node.tag == PLACEMARK_TAG:
            placemarks.append(node)
        for child in list(node):
            walk(child)

    walk(root)
    return placemarks


def sanitize_style_id(raw_id: str, fallback: str) -> str:
    candidate = re.sub(r"[^A-Za-z0-9_-]", "_", raw_id or fallback)
    if not candidate:
        candidate = fallback or "style"
    if not candidate[0].isalpha():
        candidate = f"s_{candidate}"
    return candidate


def ensure_unique_style_id(base: str, used: Set[str]) -> str:
    candidate = sanitize_style_id(base, "style")
    if candidate not in used:
        return candidate
    suffix = 1
    while True:
        alt = f"{candidate}_{suffix}"
        if alt not in used:
            return alt
        suffix += 1


def remap_style_reference(ref: str, mapping: Dict[str, str]) -> Optional[str]:
    trimmed = ref.strip()
    if not trimmed:
        return None
    if "#" in trimmed:
        prefix, key = trimmed.rsplit("#", 1)
        if key in mapping:
            return f"{prefix}#{mapping[key]}" if prefix else f"#{mapping[key]}"
        return None
    if trimmed in mapping:
        return mapping[trimmed]
    return None


def update_style_urls(element: ET.Element, mapping: Dict[str, str]) -> None:
    if not mapping:
        return
    for node in element.findall(f".//{STYLE_URL_TAG}"):
        if node.text:
            new_value = remap_style_reference(node.text, mapping)
            if new_value:
                node.text = new_value


def add_source_metadata(placemark: ET.Element, source_name: str) -> None:
    if not source_name:
        return
    extended = placemark.find(f"./{EXTENDED_DATA_TAG}")
    if extended is None:
        extended = ET.SubElement(placemark, EXTENDED_DATA_TAG)
    target = None
    for data_el in extended.findall(f"./{DATA_TAG}"):
        if data_el.get("name") == "source_file":
            target = data_el
            break
    if target is None:
        target = ET.SubElement(extended, DATA_TAG, name="source_file")
    value_el = target.find(f"./{VALUE_TAG}")
    if value_el is None:
        value_el = ET.SubElement(target, VALUE_TAG)
    value_el.text = source_name


def chunk_entries(entries: List[PlacemarkEntry], size: int) -> List[List[PlacemarkEntry]]:
    if not entries:
        return []
    if size <= 0 or len(entries) <= size:
        return [entries]
    return [entries[i:i + size] for i in range(0, len(entries), size)]


def build_document(entries: List[PlacemarkEntry], styles: Dict[str, ET.Element], title: str) -> ET.Element:
    root = ET.Element(f"{{{KML_NS}}}kml")
    document = ET.SubElement(root, DOCUMENT_TAG)
    ET.SubElement(document, NAME_TAG).text = title

    for style in styles.values():
        document.append(copy.deepcopy(style))

    folders: Dict[str, ET.Element] = {}
    for entry in entries:
        folder = folders.get(entry.source)
        if folder is None:
            folder = ET.SubElement(document, FOLDER_TAG)
            ET.SubElement(folder, NAME_TAG).text = entry.source
            folders[entry.source] = folder
        folder.append(copy.deepcopy(entry.element))

    return root


def write_kml(root: ET.Element, output_path: Path) -> None:
    tree = ET.ElementTree(root)
    tree.write(output_path, encoding="utf-8", xml_declaration=True)


def main() -> None:
    source_dir = prompt_directory()
    files = sorted(
        [path for path in source_dir.iterdir() if path.suffix.lower() in {".kml", ".kmz"}],
        key=lambda p: p.name.lower(),
    )
    if not files:
        print(f"No .kml or .kmz files found in {source_dir}")
        return

    output_dir = prompt_output_dir(source_dir)
    base_name = prompt_basename(source_dir.name)
    max_per_file = prompt_int(
        f"Max placemarks per output file [{DEFAULT_MAX_PER_FILE}]: ",
        DEFAULT_MAX_PER_FILE,
    )

    all_entries: List[PlacemarkEntry] = []
    style_library: Dict[str, ET.Element] = {}
    used_style_ids: Set[str] = set()
    style_counter = 1

    for path in files:
        try:
            root = load_kml_root(path)
        except Exception as exc:
            print(f"[skip] {path.name}: {exc}")
            continue

        style_elements = extract_style_elements(root)
        local_mapping: Dict[str, str] = {}
        assignments = []

        for style_el in style_elements:
            old_id = style_el.get("id")
            if old_id:
                base = old_id
            else:
                base = f"style_{style_counter}"
                style_counter += 1
            new_id = ensure_unique_style_id(base, used_style_ids)
            used_style_ids.add(new_id)
            assignments.append((style_el, old_id, new_id))
            if old_id:
                local_mapping[old_id] = new_id

        for original, old_id, new_id in assignments:
            style_copy = copy.deepcopy(original)
            style_copy.set("id", new_id)
            update_style_urls(style_copy, local_mapping)
            style_library[new_id] = style_copy

        placemarks = collect_placemarks(root)
        if not placemarks:
            print(f"[warn] {path.name}: no placemarks found")
            continue

        for placemark in placemarks:
            placemark_copy = copy.deepcopy(placemark)
            update_style_urls(placemark_copy, local_mapping)
            add_source_metadata(placemark_copy, path.stem)
            all_entries.append(PlacemarkEntry(placemark_copy, path.stem))

        print(f"[ok] {path.name}: collected {len(placemarks)} placemarks")

    if not all_entries:
        print("No placemarks collected; nothing to write.")
        return

    chunks = chunk_entries(all_entries, max_per_file)
    total = 0
    num_files = len(chunks)
    width = max(2, len(str(num_files)))

    for index, chunk in enumerate(chunks, 1):
        title = f"{base_name} part {index}/{num_files}"
        root = build_document(chunk, style_library, title)
        filename = f"{base_name}_part{index:0{width}d}.kml"
        destination = output_dir / filename
        write_kml(root, destination)
        total += len(chunk)
        print(f"[ok] wrote {len(chunk)} placemarks -> {destination}")

    print(
        f"[done] combined {total} placemarks from {len(files)} file(s) into {num_files} output file(s)"
    )


if __name__ == "__main__":
    main()
