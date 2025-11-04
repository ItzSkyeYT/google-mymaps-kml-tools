from pathlib import Path
from typing import List
from xml.etree import ElementTree as ET
from zipfile import ZipFile

KML_NS = "http://www.opengis.net/kml/2.2"
ET.register_namespace("", KML_NS)


def load_kml_root(path: Path) -> ET.Element:
    suffix = path.suffix.lower()
    if suffix == ".kmz":
        with ZipFile(path) as archive:
            for name in archive.namelist():
                if name.lower().endswith(".kml"):
                    data = archive.read(name)
                    return ET.fromstring(data)
        raise ValueError("KMZ archive does not contain a KML file")
    if suffix == ".kml":
        return ET.parse(path).getroot()
    raise ValueError("Unsupported file type; expected .kml or .kmz")


def collect_placemarks(element: ET.Element) -> List[ET.Element]:
    placemarks: List[ET.Element] = []

    def walk(node: ET.Element) -> None:
        if node.tag == f"{{{KML_NS}}}Placemark":
            placemarks.append(node)
        for child in list(node):
            walk(child)

    walk(element)
    return placemarks


def build_document(placemarks: List[ET.Element], name: str) -> ET.Element:
    kml = ET.Element(f"{{{KML_NS}}}kml")
    document = ET.SubElement(kml, f"{{{KML_NS}}}Document")
    folder = ET.SubElement(document, f"{{{KML_NS}}}Folder")
    ET.SubElement(folder, f"{{{KML_NS}}}name").text = name
    for placemark in placemarks:
        folder.append(placemark)
    return kml


def chunk(items: List[ET.Element], size: int) -> List[List[ET.Element]]:
    return [items[i:i + size] for i in range(0, len(items), size)]


def main() -> None:
    source = input("Enter path to KML/KMZ file: ").strip().strip('"')
    if not source:
        print("No path provided. Exiting.")
        return

    try:
        max_per_file = int(input("Max placemarks per output file [2000]: ") or "2000")
    except ValueError:
        print("Invalid number, using default 2000.")
        max_per_file = 2000
    if max_per_file <= 0:
        max_per_file = 2000

    input_path = Path(source).expanduser().resolve()
    if not input_path.is_file():
        print(f"Input file not found: {input_path}")
        return

    try:
        root = load_kml_root(input_path)
    except Exception as exc:
        print(f"Failed to read KML: {exc}")
        return

    placemarks = collect_placemarks(root)
    if not placemarks:
        print("No placemarks found in the KML.")
        return

    output_arg = input("Output directory (leave blank for default): ").strip()
    if output_arg:
        base_dir = Path(output_arg).expanduser().resolve()
    else:
        base_dir = input_path.parent
    base_dir.mkdir(parents=True, exist_ok=True)

    output_dir = base_dir / f"{input_path.stem}_split"
    output_dir.mkdir(parents=True, exist_ok=True)

    chunks = chunk(placemarks, max_per_file)
    width = max(2, len(str(len(chunks))))

    for idx, group in enumerate(chunks, 1):
        name = f"{input_path.stem} part {idx}/{len(chunks)}"
        new_root = build_document(group, name)
        out_file = output_dir / f"{input_path.stem}_part{idx:0{width}d}.kml"
        ET.ElementTree(new_root).write(out_file, encoding="utf-8", xml_declaration=True)
        print(f"[ok] part {idx}/{len(chunks)} -> {out_file} ({len(group)} placemarks)")

    print(f"Split {len(placemarks)} placemarks into {len(chunks)} file(s) under {output_dir}")


if __name__ == "__main__":
    main()