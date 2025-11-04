# google-mymaps-kml-tools
Python tools for manipulating Google My Maps KML files - split, combine, convert, and extract data from KML/KMZ files with ease.

# Google My Maps KML Tools

A collection of Python scripts for manipulating Google My Maps KML files. These tools allow you to split, combine, convert, and extract data from KML files.

## Scripts Overview

### split_kml.py
Takes a large KML/KMZ file and splits it into multiple smaller KML files while preserving all placemark data and styles. Useful when your KML file is too large to import into Google My Maps (which has a size limit).

### combine_kml_folder.py
Merges multiple KML/KMZ files from a folder into a single or multiple KML files. Handles style conflicts by remapping style IDs and preserves all placemark data. Useful for combining multiple maps into one.

### csv_or_json_to_kml.py
Converts CSV or JSON files containing location data into KML format. Expects columns/fields for coordinates (lat/lon), names, descriptions, and optionally styles and layer information. Perfect for bulk-converting location databases to Google My Maps format.

### KML_extractor.py
Extracts all placemarks and their data from a Google My Maps URL or map ID into CSV and JSON formats. Captures names, descriptions, coordinates, styles, layers, and custom fields. Useful for backing up or migrating map data.

### extract_country_kml.py
Analyzes placemarks in KML/KMZ files and splits them into separate files by country. Can use either embedded country data or reverse geocoding to determine locations. Helpful for organizing international datasets into region-specific maps.

## Requirements

- Python 3.7+
- Required packages:
  - `requests`
  - `beautifulsoup4`
  - `reverse_geocoder` (optional, for country extraction)
  - `pycountry` (optional, for country extraction)

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Split KML File

```bash
python split_kml.py
```
Follow the prompts to:
1. Enter path to source KML/KMZ file
2. Specify maximum placemarks per output file
3. Choose output directory

### Combine KML Files

```bash
python combine_kml_folder.py
```
Follow the prompts to:
1. Select folder containing KML/KMZ files
2. Choose output directory
3. Set base name for combined files
4. Specify maximum placemarks per output file

### Convert CSV/JSON to KML

```bash
python csv_or_json_to_kml.py
```
Follow the prompts to:
1. Select input CSV/JSON file
2. Choose output directory
3. Set maximum placemarks per output file

### Extract from Google My Maps

```bash
python KML_extractor.py
```
Follow the prompts to:
1. Enter Google My Maps URL or map ID
2. Set output filename base

### Extract by Country

```bash
python extract_country_kml.py
```
Follow the prompts to:
1. Select input KML/KMZ file or folder
2. Choose output directory
3. Select countries to extract
4. Set maximum placemarks per output file

## Disclaimer

These scripts are provided "as is", without warranty of any kind. Use at your own risk. The authors take no responsibility for any issues or damages that may arise from using these tools.

## Contributing

Feel free to submit issues, fork the repository, and create pull requests for any improvements.

## License

This project is licensed under the MIT License - see the LICENSE file for details.
