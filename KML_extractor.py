import base64
import csv
import json
import re
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from bs4 import BeautifulSoup

DEFAULT_OUTPUT_BASENAME = "map_points"
REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": "https://www.google.com/",
}
PAGE_DATA_RE = re.compile(r"var _pageData = \"(?P<data>.+?)\";", re.S)
APP_INITIALIZATION_STATE_RE = re.compile(r"window\.APP_INITIALIZATION_STATE=([^;]+);", re.S)
BATCH_XSSI_PREFIX = ")]}'"


def prompt_map_source() -> str:
    while True:
        try:
            value = input("Enter Google My Maps URL or map ID: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nCancelled.")
            raise SystemExit(1)
        if value:
            return value
        print("Please enter a valid URL or map identifier.")


def prompt_output_basename(default: str = DEFAULT_OUTPUT_BASENAME) -> str:
    try:
        value = input(f"Base name for output files [{default}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nCancelled.")
        raise SystemExit(1)
    return value or default


def normalize_source(source: str) -> str:
    raw = source.strip()
    if not raw:
        raise ValueError("Map identifier is empty.")
    if raw.startswith(("http://", "https://")):
        return raw
    return f"https://www.google.com/maps/d/u/0/viewer?mid={raw}"


def html_to_text(html: str) -> str:
    if not html:
        return ""
    soup = BeautifulSoup(html, "html.parser")
    return soup.get_text(" ", strip=True)


def _resolve_consent_redirect(session: requests.Session, response: requests.Response) -> requests.Response:
    if "consent.google.com" not in response.url:
        return response

    parsed = urlparse(response.url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    query.setdefault("rffu", ["true"])
    query.setdefault("ucbcb", ["1"])
    path = parsed.path
    if not path.startswith("/ml"):
        path = "/ml"
    rebuilt = urlunparse(
        parsed._replace(
            path=path,
            query=urlencode(query, doseq=True),
        )
    )
    follow = session.get(rebuilt, timeout=30)
    follow.raise_for_status()
    if "consent.google.com" in follow.url:
        continuation = query.get("continue")
        if continuation:
            cont_url = continuation[0]
            if "ucbcb=" not in cont_url:
                separator = '&' if '?' in cont_url else '?'
                cont_url = f"{cont_url}{separator}ucbcb=1"
            follow = session.get(cont_url, timeout=30)
            follow.raise_for_status()
    return follow


def fetch_page_payload(source: str) -> Dict[str, Any]:
    session = requests.Session()
    headers = dict(REQUEST_HEADERS)
    if source.startswith(("http://", "https://")):
        headers["Referer"] = source
    session.headers.update(headers)
    session.cookies.set("CONSENT", "YES+", domain=".google.com")
    resp = session.get(source, timeout=30)
    resp.raise_for_status()
    resp = _resolve_consent_redirect(session, resp)

    match = PAGE_DATA_RE.search(resp.text)
    if match:
        raw = match.group("data")
        decoded = bytes(raw, "utf-8").decode("unicode_escape")
        return {"kind": "page_data", "data": json.loads(decoded)}

    fallback = extract_app_state_payload(resp.text)
    if fallback:
        return fallback

    raise ValueError("Could not locate embedded map payload (_pageData or APP_INITIALIZATION_STATE).")


def _iter_xssi_payloads(node: Any) -> Iterable[Any]:
    stack: List[Any] = [node]
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            if current.startswith(BATCH_XSSI_PREFIX):
                _, _, remainder = current.partition("\n")
                payload_text = remainder or current[len(BATCH_XSSI_PREFIX):]
                try:
                    yield json.loads(payload_text)
                except json.JSONDecodeError:
                    continue
        elif isinstance(current, list):
            stack.extend(current)
        elif isinstance(current, dict):
            stack.extend(current.values())




def _find_placelist_payload(node: Any) -> Optional[List[Any]]:
    if isinstance(node, list):
        share_info = node[2] if len(node) > 2 else None
        features = node[8] if len(node) > 8 else None
        if (
            isinstance(share_info, list)
            and len(share_info) > 2
            and isinstance(share_info[2], str)
            and "maps/placelists/list" in share_info[2]
            and isinstance(features, list)
        ):
            return node
        for item in node:
            match = _find_placelist_payload(item)
            if match is not None:
                return match
    elif isinstance(node, dict):
        for value in node.values():
            match = _find_placelist_payload(value)
            if match is not None:
                return match
    return None




def extract_app_state_payload(html: str) -> Optional[Dict[str, Any]]:
    match = APP_INITIALIZATION_STATE_RE.search(html)
    if not match:
        return None
    try:
        app_state = json.loads(match.group(1))
    except json.JSONDecodeError:
        return None

    for candidate in _iter_xssi_payloads(app_state):
        placelist = _find_placelist_payload(candidate)
        if placelist is not None:
            return {"kind": "placelist", "data": placelist}
    return None


def first_string(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        for item in value:
            text = first_string(item)
            if text:
                return text
    return ""


def decode_key(key: str) -> str:
    if key.startswith("str:"):
        payload = key[4:]
        try:
            return base64.b64decode(payload).decode("utf-8")
        except Exception:
            return payload
    return key


def collect_fields(node: Any, bag: Dict[str, str]) -> None:
    if isinstance(node, list):
        if node and isinstance(node[0], str):
            key = decode_key(node[0])
            values = node[1] if len(node) > 1 else None
            if isinstance(values, list) and values:
                val = values[0]
                if isinstance(val, str) and key not in bag:
                    bag[key] = val
        for child in node:
            collect_fields(child, bag)


def extract_coords(feature: List[Any]) -> Optional[Tuple[float, float]]:
    coords = feature[1] if len(feature) > 1 else None
    if isinstance(coords, list) and coords:
        first = coords[0]
        if isinstance(first, list) and first:
            pair = first[0]
            if isinstance(pair, list) and len(pair) == 2:
                lat, lon = pair
                try:
                    return float(lat), float(lon)
                except (TypeError, ValueError):
                    return None
    return None


def build_style_map(layer: List[Any]) -> Dict[str, Dict[str, Any]]:
    styles = layer[4] if len(layer) > 4 and isinstance(layer[4], list) else []
    style_map: Dict[str, Dict[str, Any]] = {}

    for idx, style in enumerate(styles):
        if not isinstance(style, list):
            continue
        icon_candidates = style[0] if len(style) > 0 else None
        icon_url = icon_candidates[0] if isinstance(icon_candidates, list) and icon_candidates else ""
        categories = style[5] if len(style) > 5 else None
        style_name = first_string(categories) or "All items"
        style_id: Optional[str] = None
        features = style[6] if len(style) > 6 else None
        if isinstance(features, list):
            for feature in features:
                if isinstance(feature, list) and len(feature) > 4:
                    geometry = feature[4]
                    if isinstance(geometry, list) and len(geometry) > 3 and isinstance(geometry[3], str):
                        style_id = geometry[3]
                        break
        style_map[style_id or f"__idx_{idx}"] = {
            "name": style_name,
            "icon_url": icon_url,
            "index": idx,
        }
    return style_map


def iter_features(payload: List[Any]) -> Iterable[Dict[str, Any]]:
    if len(payload) < 2 or not isinstance(payload[1], list):
        return []

    map_data = payload[1]
    map_mid = map_data[1] if len(map_data) > 1 else ""
    map_name = map_data[2] if len(map_data) > 2 else ""
    layers = map_data[6] if len(map_data) > 6 and isinstance(map_data[6], list) else []

    for layer_index, layer in enumerate(layers):
        if not isinstance(layer, list):
            continue
        layer_id = layer[1] if len(layer) > 1 and isinstance(layer[1], str) else f"layer_{layer_index}"
        layer_name = first_string(layer[2]) or f"Layer {layer_index + 1}"
        style_map = build_style_map(layer)

        meta_entries = layer[12] if len(layer) > 12 and isinstance(layer[12], list) else []
        for style_index, meta in enumerate(meta_entries):
            if not isinstance(meta, list) or len(meta) < 14:
                continue

            style_id = meta[0] if isinstance(meta[0], str) else None
            style_info = (
                style_map.get(style_id)
                or style_map.get(f"__idx_{style_index}")
                or {"name": "All items", "icon_url": "", "index": style_index}
            )
            style_name = style_info["name"]
            icon_url = style_info.get("icon_url", "")

            details = meta[13]
            if not isinstance(details, list) or not details:
                continue
            feature_list = details[0] if len(details) > 0 else []
            style_details = details[1] if len(details) > 1 else []
            if not icon_url and isinstance(style_details, list) and style_details:
                maybe_icon = style_details[0]
                if isinstance(maybe_icon, list) and maybe_icon and isinstance(maybe_icon[0], str):
                    icon_url = maybe_icon[0]

            kml_url = meta[5] if len(meta) > 5 and isinstance(meta[5], str) else ""
            feature_list = feature_list or []

            for feature_index, feature in enumerate(feature_list):
                if not isinstance(feature, list) or len(feature) < 6:
                    continue

                coords = extract_coords(feature)
                if not coords:
                    continue
                lat, lon = coords

                attr_bag: Dict[str, str] = {}
                collect_fields(feature, attr_bag)

                name = attr_bag.pop("name", "") or attr_bag.pop("Name", "")
                description_html = attr_bag.get("description", "") or attr_bag.get("Description", "")
                description_text = html_to_text(description_html)
                link = attr_bag.get("Link(s)") or attr_bag.get("Link") or attr_bag.get("link", "")
                type_value = attr_bag.get("Type") or attr_bag.get("type", "")
                contributor = attr_bag.get("Contributor", "")
                further_reading = attr_bag.get("Further Reading", "")
                feature_id = feature[0] if isinstance(feature[0], str) else ""

                extra_fields = {
                    key: value
                    for key, value in attr_bag.items()
                    if key
                    not in {
                        "description",
                        "Description",
                        "Link(s)",
                        "Link",
                        "link",
                        "Type",
                        "type",
                        "Contributor",
                        "Further Reading",
                        "name",
                        "Name",
                    }
                }

                yield {
                    "map_mid": map_mid,
                    "map_name": map_name,
                    "layer_id": layer_id,
                    "layer": layer_name,
                    "layer_index": layer_index,
                    "style_id": style_id or f"{layer_id}_{style_index}",
                    "style": style_name,
                    "style_index": style_index,
                    "icon_url": icon_url,
                    "kml_url": kml_url,
                    "feature_id": feature_id,
                    "feature_index": feature_index,
                    "name": name,
                    "description_html": description_html,
                    "description_text": description_text,
                    "link": link,
                    "type": type_value,
                    "further_reading": further_reading,
                    "contributor": contributor,
                    "lat": lat,
                    "lon": lon,
                    "folder_path": " / ".join(segment for segment in (layer_name, style_name) if segment),
                    "extra_fields": extra_fields,
                }



def _safe_float(value: Any) -> Optional[float]:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def iter_placelist_features(placelist: List[Any]) -> Iterable[Dict[str, Any]]:
    if not isinstance(placelist, list):
        return []

    identifier = placelist[0] if len(placelist) > 0 and isinstance(placelist[0], list) else []
    map_mid = identifier[0] if isinstance(identifier, list) and identifier and isinstance(identifier[0], str) else ""
    map_name = placelist[4] if len(placelist) > 4 and isinstance(placelist[4], str) else ""
    map_description = placelist[5] if len(placelist) > 5 and isinstance(placelist[5], str) else ""
    share_info = placelist[2] if len(placelist) > 2 and isinstance(placelist[2], list) else []
    share_url = share_info[2] if isinstance(share_info, list) and len(share_info) > 2 and isinstance(share_info[2], str) else ""
    owner_info = placelist[3] if len(placelist) > 3 and isinstance(placelist[3], list) else []
    default_contributor = owner_info[0] if owner_info and isinstance(owner_info[0], str) else ""

    features = placelist[8] if len(placelist) > 8 and isinstance(placelist[8], list) else []
    layer_name = map_name or "Placelist"

    for feature_index, feature in enumerate(features):
        if not isinstance(feature, list):
            continue
        location = feature[1] if len(feature) > 1 and isinstance(feature[1], list) else []

        lat = lon = None
        if isinstance(location, list) and len(location) > 5 and isinstance(location[5], list):
            coord_block = location[5]
            lat = _safe_float(coord_block[2] if len(coord_block) > 2 else None)
            lon = _safe_float(coord_block[3] if len(coord_block) > 3 else None)
        if (lat is None or lon is None) and isinstance(location, list) and len(location) > 4:
            raw_pair = location[4]
            if isinstance(raw_pair, str) and "," in raw_pair:
                lat_str, lon_str = raw_pair.split(",", 1)
                lat = _safe_float(lat_str)
                lon = _safe_float(lon_str)
        if lat is None or lon is None:
            continue

        name = feature[2] if len(feature) > 2 and isinstance(feature[2], str) else ""
        description = feature[3] if len(feature) > 3 and isinstance(feature[3], str) else ""

        address = location[2] if isinstance(location, list) and len(location) > 2 and isinstance(location[2], str) else ""
        location_hint = location[4] if isinstance(location, list) and len(location) > 4 and isinstance(location[4], str) else ""
        place_ids_container = location[6] if isinstance(location, list) and len(location) > 6 else None
        place_ids = [pid for pid in place_ids_container if isinstance(pid, str)] if isinstance(place_ids_container, list) else []
        plus_code = location[7] if isinstance(location, list) and len(location) > 7 and isinstance(location[7], str) else ""

        contributor = default_contributor
        contributor_candidates = feature[18] if len(feature) > 18 and isinstance(feature[18], list) else None
        if isinstance(contributor_candidates, list) and contributor_candidates:
            first_candidate = contributor_candidates[0]
            if isinstance(first_candidate, list) and first_candidate and isinstance(first_candidate[0], str):
                contributor = first_candidate[0]

        feature_id = place_ids[0] if place_ids else (plus_code or f"placelist_{feature_index}")
        if place_ids:
            link = f"https://www.google.com/maps/place/?q=place_id:{place_ids[0]}"
        else:
            link = f"https://www.google.com/maps/search/?api=1&query={lat},{lon}"

        extra_fields: Dict[str, Any] = {}
        if address:
            extra_fields["address"] = address
        if location_hint and location_hint != address:
            extra_fields["location_hint"] = location_hint
        if place_ids:
            extra_fields["place_ids"] = place_ids
        if plus_code:
            extra_fields["plus_code"] = plus_code
        if share_url:
            extra_fields["list_share_url"] = share_url
        if map_description:
            extra_fields["map_description"] = map_description
        extra_fields["source"] = "google_maps_list"

        yield {
            "map_mid": map_mid,
            "map_name": map_name,
            "layer_id": "placelist",
            "layer": layer_name,
            "layer_index": 0,
            "style_id": "placelist_default",
            "style": "Default",
            "style_index": 0,
            "icon_url": "",
            "kml_url": "",
            "feature_id": feature_id,
            "feature_index": feature_index,
            "name": name,
            "description_html": description,
            "description_text": description,
            "link": link,
            "type": "Placelist item",
            "further_reading": "",
            "contributor": contributor,
            "lat": float(lat),
            "lon": float(lon),
            "folder_path": layer_name,
            "extra_fields": extra_fields,
        }

def main() -> None:
    source_input = prompt_map_source()
    source_url = normalize_source(source_input)
    print(f"[info] Fetching map data from {source_url}")
    payload_info = fetch_page_payload(source_url)
    payload_kind = payload_info.get("kind")
    payload_data = payload_info.get("data")

    if payload_kind == "page_data":
        rows = list(iter_features(payload_data))
    elif payload_kind == "placelist":
        print("[info] Detected Google Maps list format; extracting items")
        rows = list(iter_placelist_features(payload_data))
    else:
        raise SystemExit("Unsupported or unrecognized map payload format.")

    if not rows:
        raise SystemExit("No points extracted.")

    rows.sort(key=lambda r: (r["layer_index"], r["style_index"], r["feature_index"]))
    output_basename = prompt_output_basename()

    csv_fieldnames = [
        "map_mid",
        "map_name",
        "layer_id",
        "layer",
        "layer_index",
        "style_id",
        "style",
        "style_index",
        "icon_url",
        "kml_url",
        "feature_id",
        "feature_index",
        "name",
        "description_text",
        "description_html",
        "type",
        "link",
        "further_reading",
        "contributor",
        "lat",
        "lon",
        "folder_path",
        "extra_fields",
    ]

    csv_rows: List[Dict[str, Any]] = []
    for row in rows:
        csv_row = {key: row.get(key, "") for key in csv_fieldnames}
        csv_row["lat"] = f"{row['lat']}"
        csv_row["lon"] = f"{row['lon']}"
        extra = row.get("extra_fields") or {}
        csv_row["extra_fields"] = json.dumps(extra, ensure_ascii=False, sort_keys=True) if extra else ""
        csv_rows.append(csv_row)

    csv_path = f"{output_basename}.csv"
    json_path = f"{output_basename}.json"

    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=csv_fieldnames)
        writer.writeheader()
        writer.writerows(csv_rows)

    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(rows, handle, ensure_ascii=False, indent=2)

    print(f"[ok] Extracted {len(rows)} points")
    print(f"     {csv_path}")
    print(f"     {json_path}")


if __name__ == "__main__":
    main()
