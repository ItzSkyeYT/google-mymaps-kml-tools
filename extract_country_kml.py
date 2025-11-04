import copy
import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from xml.etree import ElementTree as ET
from zipfile import ZipFile

try:
    import reverse_geocoder as rg
except ImportError:  # pragma: no cover - optional dependency
    rg = None

try:
    import pycountry
except ImportError:  # pragma: no cover - optional dependency
    pycountry = None

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
SIMPLE_DATA_TAG = f"{{{KML_NS}}}SimpleData"
COORDINATES_TAG = f"{{{KML_NS}}}coordinates"

COUNTRY_OVERRIDES = {
    "AX": "Aland Islands",
    "BL": "Saint Barthelemy",
    "BQ": "Caribbean Netherlands",
    "CW": "Curacao",
    "GG": "Guernsey",
    "IM": "Isle of Man",
    "JE": "Jersey",
    "MF": "Saint Martin",
    "PS": "Palestine",
    "SX": "Sint Maarten",
    "XK": "Kosovo",
}

ET.register_namespace("", KML_NS)


@dataclass
class PlacemarkEntry:
    element: ET.Element
    source: str
    countries: Set[str]


def prompt_input_path() -> Path:
    while True:
        try:
            raw = input("Enter KML/KMZ file or directory: ").strip().strip('"')
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            raise SystemExit(1)
        if not raw:
            print("Please enter a path.")
            continue
        path = Path(raw).expanduser().resolve()
        if not path.exists():
            print(f"Path not found: {path}")
            continue
        if path.is_file() and path.suffix.lower() not in {".kml", ".kmz"}:
            print("Expected a .kml, .kmz, or a directory.")
            continue
        return path


def prompt_output_dir(reference: Path) -> Path:
    try:
        raw = input("Output directory (leave blank for default): ").strip().strip('"')
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        raise SystemExit(1)
    base = Path(raw).expanduser().resolve() if raw else (reference.parent if reference.is_file() else reference)
    base.mkdir(parents=True, exist_ok=True)
    output = base / f"{reference.stem if reference.is_file() else reference.name}_by_country"
    output.mkdir(parents=True, exist_ok=True)
    return output



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


def prompt_country_selection(options: List[str]) -> List[str]:
    if not options:
        return []
    print("Available countries:")
    for idx, name in enumerate(options, 1):
        print(f"  {idx:>3}. {name}")
    while True:
        try:
            raw = input("Select countries (* for all, numbers or names separated by commas): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            raise SystemExit(1)
        if not raw:
            print("Please enter a selection.")
            continue
        if raw in {"*", "all", "ALL"}:
            return options
        tokens = [token.strip() for token in re.split(r"[,;]", raw) if token.strip()]
        chosen: List[str] = []
        for token in tokens:
            if token.isdigit():
                idx = int(token)
                if 1 <= idx <= len(options):
                    value = options[idx - 1]
                else:
                    print(f"Index out of range: {token}")
                    value = None
            else:
                matches = [name for name in options if name.lower() == token.lower()]
                if matches:
                    value = matches[0]
                else:
                    subset = [name for name in options if token.lower() in name.lower()]
                    if len(subset) == 1:
                        value = subset[0]
                    elif subset:
                        print(f"Ambiguous selection '{token}': {', '.join(subset)}")
                        value = None
                    else:
                        print(f"No match for '{token}'.")
                        value = None
            if value and value not in chosen:
                chosen.append(value)
        if chosen:
            return chosen
        print("No valid selections. Try again.")


def resolve_input_files(path: Path) -> List[Path]:
    if path.is_file():
        return [path]
    files = sorted((p for p in path.iterdir() if p.suffix.lower() in {".kml", ".kmz"}), key=lambda p: p.name.lower())
    return files


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


def iter_documents(root: ET.Element) -> Iterable[ET.Element]:
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
    if not ref:
        return None
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


def extract_country_values(placemark: ET.Element) -> List[str]:
    values: List[str] = []
    for data_el in placemark.findall(f".//{DATA_TAG}"):
        name = (data_el.get("name") or "").strip().lower()
        if name == "country":
            value_el = data_el.find(f"./{VALUE_TAG}")
            if value_el is not None and value_el.text:
                values.append(value_el.text)
    for simple in placemark.findall(f".//{SIMPLE_DATA_TAG}"):
        name = (simple.get("name") or "").strip().lower()
        if name == "country" and simple.text:
            values.append(simple.text)
    return values


def split_country_tokens(value: str) -> Iterable[str]:
    for token in re.split(r"[;,/|]", value):
        text = re.sub(r"\s+", " ", token).strip()
        if text:
            yield text


def register_country(value: str, registry: Dict[str, str]) -> Optional[str]:
    normalized = re.sub(r"\s+", " ", value).strip()
    if not normalized:
        return None
    key = normalized.casefold()
    if key not in registry:
        registry[key] = normalized
    return registry[key]


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


def parse_coordinates(text: str) -> Optional[Tuple[float, float]]:
    if not text:
        return None
    for chunk in re.split(r"\s+", text.strip()):
        if not chunk:
            continue
        parts = chunk.split(",")
        if len(parts) >= 2:
            try:
                lon = float(parts[0])
                lat = float(parts[1])
            except ValueError:
                continue
            return lat, lon
    return None


def extract_primary_coordinate(placemark: ET.Element) -> Optional[Tuple[float, float]]:
    for node in placemark.findall(f".//{COORDINATES_TAG}"):
        coords = parse_coordinates(node.text or "")
        if coords:
            return coords
    return None


def iso_to_country_name(code: str) -> Optional[str]:
    if not code:
        return None
    code = code.upper()
    if pycountry:
        try:
            country = pycountry.countries.get(alpha_2=code)
            if country:
                return country.name
        except LookupError:
            pass
    return COUNTRY_OVERRIDES.get(code, code)


@lru_cache(maxsize=8192)
def _geocode_country(lat: float, lon: float) -> Optional[str]:
    if rg is None:
        return None
    try:
        result = rg.search((lat, lon), mode=1)
    except Exception:
        return None
    if not result:
        return None
    code = result[0].get("cc")
    return iso_to_country_name(code)


def lookup_country_by_coords(coords: Tuple[float, float]) -> Optional[str]:
    lat, lon = coords
    rounded_lat = round(lat, 5)
    rounded_lon = round(lon, 5)
    return _geocode_country(rounded_lat, rounded_lon)


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


def sanitize_filename(value: str) -> str:
    sanitized = re.sub(r"[\\/:*?\"<>|]", "_", value)
    sanitized = re.sub(r"\s+", "_", sanitized)
    return sanitized or "country"


def main() -> None:
    if rg is None:
        print(
            "reverse_geocoder is required for coordinate lookup. Install it with 'pip install reverse_geocoder'."
        )
        return

    input_path = prompt_input_path()
    files = resolve_input_files(input_path)
    if not files:
        print("No .kml or .kmz files found.")
        return

    output_dir = prompt_output_dir(input_path)
    max_per_file = prompt_int(
        f"Max placemarks per output file [{DEFAULT_MAX_PER_FILE}]: ",
        DEFAULT_MAX_PER_FILE,
    )

    country_registry: Dict[str, str] = {}
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
            base = old_id or f"style_{style_counter}"
            if not old_id:
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
            coords = extract_primary_coordinate(placemark)
            placemark_copy = copy.deepcopy(placemark)
            update_style_urls(placemark_copy, local_mapping)
            add_source_metadata(placemark_copy, path.stem)

            countries: Set[str] = set()
            for value in extract_country_values(placemark):
                for token in split_country_tokens(value):
                    registered = register_country(token, country_registry)
                    if registered:
                        countries.add(registered)

            if coords:
                geocoded = lookup_country_by_coords(coords)
                if geocoded:
                    registered = register_country(geocoded, country_registry)
                    if registered:
                        countries.add(registered)

            if not countries:
                continue

            all_entries.append(PlacemarkEntry(placemark_copy, path.stem, countries))

        print(f"[ok] {path.name}: tracked {len(placemarks)} placemarks")

    if not all_entries:
        print("No placemarks with country metadata were collected.")
        return

    available_countries = sorted(country_registry.values())
    selected_countries = prompt_country_selection(available_countries)
    if not selected_countries:
        print("No countries selected. Nothing to do.")
        return

    for country in selected_countries:
        subset = [entry for entry in all_entries if country in entry.countries]
        if not subset:
            print(f"[warn] No placemarks found for {country}.")
            continue
        country_slug = sanitize_filename(country)
        country_dir = output_dir / country_slug
        country_dir.mkdir(parents=True, exist_ok=True)
        chunks = chunk_entries(subset, max_per_file)
        padding = max(2, len(str(len(chunks))))
        for index, chunk in enumerate(chunks, 1):
            title = f"{country} part {index}/{len(chunks)}"
            root = build_document(chunk, style_library, title)
            filename = f"{country_slug}_part{index:0{padding}d}.kml"
            destination = country_dir / filename
            write_kml(root, destination)
            print(f"[ok] {country}: wrote {len(chunk)} placemarks -> {destination}")

    print("[done] Finished exporting selected countries.")


if __name__ == "__main__":
    main()






