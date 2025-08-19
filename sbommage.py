#!/usr/bin/env python
import json
import sys
import re
from textual.app import App
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Tree, Footer, Static
from textual.widgets import Markdown
from typing import Dict, Any
from pathlib import Path
        
def format_urls_as_markdown(text):
    """Convert plain URLs in text to markdown links, skipping already formatted markdown links."""
    # Skip URLs that are already in markdown format [text](url)
    if re.search(r'\[.+?\]\(.+?\)', text):
        return text
    
    # Convert plain URLs to markdown links
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[^)\s]*)?'
    return re.sub(url_pattern, lambda m: f'[{m.group()}]({m.group()})', text)

class SearchState:
    def __init__(self):
        self.active = False
        self.query = ""
        self.current_matches = []
        self.current_match_index = -1

class SBOMFormatDetector:
    """Detect the format of an SBOM file."""
    
    @staticmethod
    def detect_format(content: Dict[Any, Any]) -> str:
        """
        Detect the SBOM format based on content markers.
        Returns: 'spdx', 'cyclonedx', 'syft', 'github', or 'unknown'
        """
        # SPDX typically has a spdxVersion field
        if 'spdxVersion' in content:
            return 'spdx'
        
        # CycloneDX has a bomFormat field
        if 'bomFormat' in content and content['bomFormat'] == 'CycloneDX':
            return 'cyclonedx'
        
        # GitHub dependency graph format has detector and manifests fields
        if 'detector' in content and 'manifests' in content and 'version' in content:
            return 'github'
        
        # Syft has a specific descriptor and schema
        if 'descriptor' in content and 'schema' in content:
            return 'syft'
            
        return 'unknown'

class SBOMParser:
    """Parse different SBOM formats into a common structure."""
    
    @staticmethod
    def parse_spdx(content: Dict[Any, Any]) -> Dict[str, Any]:
        packages = []
        if 'packages' in content:
            for pkg in content['packages']:
                packages.append({
                    'name': pkg.get('name', 'Unknown'),
                    'version': pkg.get('versionInfo', 'Unknown'),
                    'type': pkg.get('type', 'Unknown'),
                    'supplier': pkg.get('supplier', 'Unknown'),
                    'license': pkg.get('licenseConcluded', 'Unknown'),
                })
        return {
            'format': 'SPDX',
            'version': content.get('spdxVersion', 'Unknown'),
            'packages': packages
        }

    @staticmethod
    def parse_cyclonedx(content: Dict[Any, Any]) -> Dict[str, Any]:
        packages = []
        if 'components' in content:
            for comp in content['components']:
                packages.append({
                    'name': comp.get('name', 'Unknown'),
                    'version': comp.get('version', 'Unknown'),
                    'type': comp.get('type', 'Unknown'),
                    'supplier': comp.get('publisher', 'Unknown'),
                    'license': comp.get('licenses', [{}])[0].get('license', {}).get('id', 'Unknown'),
                })
        return {
            'format': 'CycloneDX',
            'version': content.get('specVersion', 'Unknown'),
            'packages': packages
        }

    @staticmethod
    def parse_syft(content: Dict[Any, Any]) -> Dict[str, Any]:
        packages = []
        metadata = {
            'distro': {},
            'source': {},
            'schema': {}
        }

        # Get artifacts/packages
        CHUNK_SIZE = 1000  # Process artifacts in chunks to manage memory
        packages = []
        
        if 'artifacts' in content:
            artifacts = content['artifacts']
            for i in range(0, len(artifacts), CHUNK_SIZE):
                chunk = artifacts[i:i + CHUNK_SIZE]
                for artifact in chunk:
                    # Handle the more complex license structure
                    licenses = artifact.get('licenses', [])
                    license_info = []
                    for lic in licenses:
                        # Safely get location path with fallback
                        locations = lic.get('locations', [])
                        location_path = locations[0].get('path', 'Unknown') if locations else 'Unknown'
                        
                        license_info.append({
                            'value': lic.get('value', 'Unknown'),
                            'type': lic.get('type', 'Unknown'),
                            'spdxExpression': lic.get('spdxExpression', ''),
                            'location': location_path
                        })
                    
                    # More robust license string handling
                    license_str = license_info[0]['value'] if license_info else 'Unknown'
                    
                    upstreams = artifact.get('upstreams', [])
                    supplier = upstreams[0].get('name', 'Unknown') if upstreams else 'Unknown'
                    
                    packages.append({
                        'name': artifact.get('name', 'Unknown'),
                        'version': artifact.get('version', 'Unknown'),
                        'type': artifact.get('type', 'Unknown'),
                        'supplier': supplier,
                        'license': license_str,
                        'license_info': license_info
                    })

        # Get distro information
        if 'distro' in content:
            metadata['distro'] = {
                'name': content['distro'].get('prettyName', 'Unknown'),
                'version': content['distro'].get('version', 'Unknown'),
                'id': content['distro'].get('id', 'Unknown')
            }

        # Get source information (container metadata)
        if 'source' in content:
            source = content['source']
            metadata['source'] = {
                'type': source.get('type', 'Unknown'),
                'name': source.get('name', 'Unknown'),
                'version': source.get('version', 'Unknown')
            }
            if 'metadata' in source:
                metadata['source']['image_size'] = source['metadata'].get('imageSize', 'Unknown')
                metadata['source']['architecture'] = source['metadata'].get('architecture', 'Unknown')
                metadata['source']['os'] = source['metadata'].get('os', 'Unknown')

        # Get schema information
        if 'schema' in content:
            metadata['schema'] = {
                'version': content['schema'].get('version', 'Unknown'),
                'url': content['schema'].get('url', 'Unknown')
            }

        return {
            'format': 'Syft',
            'version': content.get('schema', {}).get('version', 'Unknown'),
            'packages': packages,
            'metadata': metadata
        }

    @staticmethod
    def parse_github(content: Dict[Any, Any]) -> Dict[str, Any]:
        """
        Parse a GitHub dependency graph SBOM format into a common structure.

        The expected input is a dictionary representing the JSON content of a GitHub dependency graph export.
        The format typically includes the following top-level fields:
            - 'detector': Information about the tool that generated the dependency graph (name, version, url).
            - 'manifests': A dictionary where each key is a manifest file path and each value contains a list of resolved dependencies.
            - 'version': The version of the dependency graph format.
            - 'scanned': (optional) Timestamp of when the scan was performed.

        Each manifest entry contains:
            - 'resolved': A dictionary of dependencies, where each key is a package name and the value contains:
                - 'package_url': A purl (package URL) string identifying the package.
                - 'metadata': (optional) Additional metadata about the package.

        The method parses each manifest and extracts package information, including the package URL (purl),
        name, version, and any available metadata. It also collects detector and scan metadata.

        Returns:
            A dictionary with the following structure:
                - 'format': 'GitHub'
                - 'version': The version of the dependency graph format.
                - 'packages': A list of parsed package dictionaries, each containing at least 'purl', 'name', 'version', and 'manifest'.
                - 'metadata': A dictionary with detector information and scan timestamp.
        """
        import urllib.parse
        
        packages = []
        metadata = {
            'detector': {},
            'scanned': ''
        }

        # Get detector information
        if 'detector' in content:
            detector = content['detector']
            metadata['detector'] = {
                'name': detector.get('name', 'Unknown'),
                'version': detector.get('version', 'Unknown'),
                'url': detector.get('url', 'Unknown')
            }

        # Get scan timestamp
        metadata['scanned'] = content.get('scanned', 'Unknown')

        # Extract packages from manifests
        if 'manifests' in content:
            for manifest_key, manifest_data in content['manifests'].items():
                if 'resolved' in manifest_data:
                    for package_url, package_info in manifest_data['resolved'].items():
                        # Parse package URL (format: pkg:type/namespace/name@version?params)
                        name = 'Unknown'
                        version = 'Unknown'
                        package_type = 'Unknown'
                        namespace = ''
                        
                        try:
                            # Basic package URL parsing
                            if package_url.startswith('pkg:'):
                                # Remove query parameters first
                                url_without_params = package_url.split('?')[0]
                                
                                # Split by '/' to get components
                                parts = url_without_params.split('/')
                                
                                if len(parts) >= 3:
                                    # Extract type (e.g., deb, nuget, npm, apk)
                                    type_part = parts[0].split(':')[1]  # Remove 'pkg:'
                                    package_type = type_part
                                    
                                    # Handle different package URL formats
                                    if len(parts) == 3:
                                        # Format: pkg:type/namespace/name@version
                                        namespace = parts[1]
                                        name_version = parts[2]
                                    elif len(parts) == 4:
                                        # Format: pkg:type/namespace/subnamespace/name@version
                                        namespace = f"{parts[1]}/{parts[2]}"
                                        name_version = parts[3]
                                    else:
                                        # Handle other formats by joining middle parts as namespace
                                        namespace = '/'.join(parts[1:-1])
                                        name_version = parts[-1]
                                    
                                    # Extract name and version
                                    if '@' in name_version:
                                        name_parts = name_version.split('@', 1)  # Split only on first '@'
                                        name = name_parts[0]
                                        version = urllib.parse.unquote(name_parts[1])  # URL decode version
                                    else:
                                        name = name_version
                                        
                                elif len(parts) == 2:
                                    # Format: pkg:type/name@version (no namespace)
                                    type_part = parts[0].split(':')[1]  # Remove 'pkg:'
                                    package_type = type_part
                                    name_version = parts[1]
                                    
                                    if '@' in name_version:
                                        name_parts = name_version.split('@', 1)
                                        name = name_parts[0]
                                        version = urllib.parse.unquote(name_parts[1])
                                    else:
                                        name = name_version
                                        
                        except (IndexError, AttributeError) as e:
                            logging.warning(f"Failed to parse package URL '{package_url}': {e}")
                            # Fallback to using the full package_url as name
                            name = package_url

                        # Create package entry
                        packages.append({
                            'name': name,
                            'version': version,
                            'type': package_type,
                            'supplier': namespace if namespace else 'Unknown',
                            'license': 'Unknown',  # GitHub format doesn't include license info
                            'package_url': package_url,
                            'relationship': package_info.get('relationship', 'Unknown'),
                            'scope': package_info.get('scope', 'Unknown'),
                            'source_location': manifest_data.get('file', {}).get('source_location', 'Unknown')
                        })

        return {
            'format': 'GitHub',
            'version': content.get('version', 'Unknown'),
            'packages': packages,
            'metadata': metadata
        }

    @classmethod
    def parse(cls, content: Dict[Any, Any], format_type: str) -> Dict[str, Any]:
        """Parse SBOM content based on detected format."""
        if format_type == 'spdx':
            return cls.parse_spdx(content)
        elif format_type == 'cyclonedx':
            return cls.parse_cyclonedx(content)
        elif format_type == 'syft':
            return cls.parse_syft(content)
        elif format_type == 'github':
            return cls.parse_github(content)
        else:
            raise ValueError(f"Unsupported SBOM format: {format_type}")

class Sbommage(App):
    """A TUI for viewing Software Bill of Materials (SBOM) files."""

    BINDINGS = [
        ("/", "start_search", "Search"),
        ("n", "load_tree_by_name", "by Name"),
        ("t", "load_tree_by_type", "by Type"),
        ("c", "load_tree_by_license", "by License"),  # Changed from 'l' to 'c'
        ("s", "load_tree_by_supplier", "by Supplier"),
        ("j", "simulate_key('down')", "Down"),
        ("k", "simulate_key('up')", "Up"),
        ("h", "simulate_key('left')", "Left"),
        ("l", "simulate_key('right')", "Right"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, sbom_file=None):
        super().__init__()
        self.sbom_file = sbom_file
        self.sbom_data = None
        try:
            self.debug_log_file = open("sbommage_debug.txt", "w")
        except PermissionError:
            # Fallback to /tmp or disable debug logging if no write permissions
            import tempfile
            try:
                self.debug_log_file = tempfile.NamedTemporaryFile(mode="w", prefix="sbommage_debug_", suffix=".txt", delete=False)
            except:
                self.debug_log_file = None
        # Add a constant for the root label
        self.ROOT_LABEL = "SBOM Contents"
        self.search_state = SearchState()

    def action_start_search(self):
        """Start search mode."""
        self.search_state.active = True
        # Don't reset query, keep the previous one
        self.status_bar.update(f"Search: {self.search_state.query}")

    def find_matches(self, query: str) -> list:
        """Find all nodes matching the search query."""
        matches = []
        
        def search_node(node):
            # Get the label as string
            label_str = str(node.label)
            
            # Check if this node matches
            if query.lower() in label_str.lower():
                matches.append(node)
            
            # If this node has any children, search them too
            if len(node.children) > 0:  # Check children length
                # Get all children, whether visible or not
                for child in node.children:
                    search_node(child)
        
        search_node(self.tree_view.root)
        return matches

    def update_live_search(self, key: str):
        """Update search results as user types."""
        if key == "enter":
            self.search_state.active = False
            self.status_bar.update("Status: Search complete")
            return
        
        # Update query
        if key == "backspace":
            self.search_state.query = self.search_state.query[:-1]
        else:
            self.search_state.query += key
        
        # Find matches
        matches = self.find_matches(self.search_state.query)
        self.search_state.current_matches = matches
        self.search_state.current_match_index = 0
        
        # Update status bar with current search
        self.status_bar.update(f"Search: {self.search_state.query}")
        
        # If we have matches, highlight the first one and ensure its parent nodes are expanded
        if matches:
            match_node = matches[0]
            # Expand all parent nodes to make the match visible
            parent = match_node.parent
            while parent is not None:
                parent.expand()
                parent = parent.parent
            self.tree_view.select_node(match_node)
            self.tree_view.scroll_to_node(match_node)

    def debug_log(self, message):
        """Helper method to write debug messages to log file."""
        if self.debug_log_file:
            self.debug_log_file.write(f"{message}\n")
            self.debug_log_file.flush()

    async def on_mount(self):
        """Set up the user interface."""
        self.debug_log("on_mount: Starting application setup")

        # Initialize widgets
        self.tree_view = Tree("Components")
        self.details_display = Markdown("Select a component for more details.")
        self.status_bar = Static("Status: Initializing...")

        # Create containers
        tree_container = Container(self.tree_view)
        details_container = VerticalScroll(self.details_display)
        
        # Set layout proportions
        tree_container.styles.width = "35%"
        details_container.styles.width = "65%"
        tree_container.styles.height = "98%"
        details_container.styles.height = "98%"

        # Create main layout
        main_layout = Horizontal(tree_container, details_container)
        main_layout.styles.height = "98%"

        # Mount layouts
        await self.mount(main_layout)
        await self.mount(self.status_bar)
        await self.mount(Footer())
        
        self.debug_log("on_mount: Layout mounted")

        # Load the SBOM file
        await self.load_sbom()

    async def on_key(self, event):
        """Handle key press events."""
        key = event.key.lower()
        
        # If search is active, handle search input and prevent event propagation
        if self.search_state.active:
            event.prevent_default()  # Prevent the event from reaching the tree
            if len(key) == 1:  # Single character
                self.update_live_search(key)
            elif key == "enter":
                self.update_live_search("enter")
            elif key == "backspace":
                self.update_live_search("backspace")
            return
        
        # Normal key handling
        if key == "/":
            event.prevent_default()  # Prevent the "/" from reaching the tree
            self.action_start_search()
        elif key == "n":
            self.load_tree_by_name()
            self.status_bar.update("Status: Viewing by package name.")
        elif key == "t":
            self.load_tree_by_type()
            self.status_bar.update("Status: Viewing by package type.")
        elif key == "c":  # Changed from 'l' to 'c'
            self.load_tree_by_license()
            self.status_bar.update("Status: Viewing by license.")
        elif key == "s":
            self.load_tree_by_supplier()
            self.status_bar.update("Status: Viewing by supplier.")

    async def load_sbom(self):
        """Load and parse the SBOM file."""
        if not self.sbom_file:
            self.status_bar.update("Status: No SBOM file provided")
            return

        try:
            with open(self.sbom_file, 'r', encoding='utf-8') as f:
                content = json.load(f)
            
            # Detect format
            format_type = SBOMFormatDetector.detect_format(content)
            self.debug_log(f"Detected SBOM format: {format_type}")
            
            if format_type == 'unknown':
                print("Error: Unknown SBOM format - supported formats: SPDX, CycloneDX, Syft, GitHub dependency graph", file=sys.stderr)
                sys.exit(1)
                
            # Parse content
            try:
                self.sbom_data = SBOMParser.parse(content, format_type)
                self.load_tree_by_name()
                self.status_bar.update(f"Status: Loaded {format_type.upper()} SBOM. Press N, T, C, S to change views.")  # Changed from N, T, L, S
            except Exception as parse_error:
                self.debug_log(f"Error parsing SBOM: {str(parse_error)}")
                self.status_bar.update(f"Status: Error parsing SBOM - {str(parse_error)}")
                
        except json.JSONDecodeError as e:
            self.debug_log(f"Error decoding JSON: {str(e)}")
            self.status_bar.update("Status: Invalid JSON file")
        except Exception as e:
            self.debug_log(f"Error loading SBOM: {str(e)}")
            self.status_bar.update(f"Status: Error loading SBOM - {str(e)}")

    def _add_metadata_nodes(self, root_node):
        """Helper to add metadata nodes consistently across all views."""
        if not self.sbom_data or 'metadata' not in self.sbom_data:
            return
            
        meta = self.sbom_data['metadata']
        
        # Distribution info
        if 'distro' in meta:
            distro_node = root_node.add_leaf("Distribution")
            distro_node.data = {'type': 'distro', 'info': meta['distro']}
            
        # Source/container info
        if 'source' in meta:
            source_node = root_node.add_leaf("Source")
            source_node.data = {'type': 'source', 'info': meta['source']}
            
        # Schema info
        if 'schema' in meta:
            schema_node = root_node.add_leaf("Schema")
            schema_node.data = {'type': 'schema', 'info': meta['schema']}

    def load_tree_by_name(self):
        """Display components organized by name."""
        self.tree_view.clear()
        self.tree_view.root.label = self.ROOT_LABEL + " by Name"
        
        # Add metadata nodes
        self._add_metadata_nodes(self.tree_view.root)

        # Add packages under a "Packages" node
        packages_node = self.tree_view.root.add("Packages")
        if 'packages' in self.sbom_data:
            for package in sorted(self.sbom_data['packages'], key=lambda x: x['name']):
                node = packages_node.add_leaf(package['name'])
                node.data = {'type': 'package', 'info': package}

    def load_tree_by_type(self):
        """Display components organized by type."""
        self.tree_view.clear()
        self.tree_view.root.label = self.ROOT_LABEL + " by Type"
        
        # Add metadata nodes
        self._add_metadata_nodes(self.tree_view.root)

        # Add packages grouped by type
        if not self.sbom_data or 'packages' not in self.sbom_data:
            return

        packages_node = self.tree_view.root.add("Package types")
        # Group packages by type
        type_map = {}
        for package in self.sbom_data['packages']:
            pkg_type = package['type']
            if pkg_type not in type_map:
                type_map[pkg_type] = []
            type_map[pkg_type].append(package)

        # Add to tree
        for pkg_type in sorted(type_map.keys()):
            type_node = packages_node.add(pkg_type)
            for package in sorted(type_map[pkg_type], key=lambda x: x['name']):
                node = type_node.add_leaf(package['name'])
                node.data = {'type': 'package', 'info': package}

    def load_tree_by_license(self):
        """Display components organized by license."""
        self.tree_view.clear()
        self.tree_view.root.label = self.ROOT_LABEL + " by License"
        
        # Add metadata nodes
        self._add_metadata_nodes(self.tree_view.root)

        if not self.sbom_data or 'packages' not in self.sbom_data:
            return

        packages_node = self.tree_view.root.add("Licenses")
        # Group packages by license
        license_map = {}
        for package in self.sbom_data['packages']:
            license_id = package['license']  # This is now the simplified license value
            if license_id not in license_map:
                license_map[license_id] = []
            license_map[license_id].append(package)

        # Add to tree
        for license_id in sorted(license_map.keys()):
            license_node = packages_node.add(license_id)
            for package in sorted(license_map[license_id], key=lambda x: x['name']):
                node = license_node.add_leaf(package['name'])
                node.data = {'type': 'package', 'info': package}

    def load_tree_by_supplier(self):
        """Display components organized by supplier."""
        self.tree_view.clear()
        self.tree_view.root.label = self.ROOT_LABEL + " by Supplier"
        
        # Add metadata nodes
        self._add_metadata_nodes(self.tree_view.root)

        # Add packages grouped by supplier
        if not self.sbom_data or 'packages' not in self.sbom_data:
            return

        packages_node = self.tree_view.root.add("Suppliers")
        # Group packages by supplier
        supplier_map = {}
        for package in self.sbom_data['packages']:
            supplier = package['supplier']
            if supplier not in supplier_map:
                supplier_map[supplier] = []
            supplier_map[supplier].append(package)

        # Add to tree
        for supplier in sorted(supplier_map.keys()):
            supplier_node = packages_node.add(supplier)
            for package in sorted(supplier_map[supplier], key=lambda x: x['name']):
                node = supplier_node.add_leaf(package['name'])
                node.data = {'type': 'package', 'info': package}

    async def on_tree_node_selected(self, event):
        """Show detailed information for the selected component."""
        node = event.node
        if not node.data:
            return
            
        data_type = node.data.get('type', '')
        info = node.data.get('info', {})
        
        if data_type == 'package':
            detail_text = (
                f"# Package Details\n\n"
                f"**Name:** {info['name']}\n\n"
                f"**Version:** {info['version']}\n\n"
                f"**Type:** {info['type']}\n\n"
                f"**Supplier:** {info['supplier']}\n\n"
            )

            # Only show license info table if there is any
            if 'license_info' in info and len(info['license_info']) > 0:
                detail_text += "## License Information\n\n"
                detail_text += "| Value | SPDX | Type | Location |\n"
                detail_text += "| --- | --- | --- | --- |\n"
                for lic in info['license_info']:
                    detail_text += f"| {lic['value']} |"
                    if lic['spdxExpression']:
                        detail_text += f" {lic['spdxExpression']} |"
                    else:
                        detail_text += " |"
                    detail_text += f" {lic['type']} | {lic['location']} |\n"

        elif data_type == 'distro':
            detail_text = (
                f"# Distribution Details\n\n"
                f"**Name:** {info['name']}\n\n"
                f"**Version:** {info['version']}\n\n"
                f"**ID:** {info['id']}\n\n"
            )
        elif data_type == 'source':
            detail_text = (
                f"# Source Details\n\n"
                f"**Type:** {info['type']}\n\n"
                f"**Name:** {info['name']}\n\n"
                f"**Version:** {info['version']}\n\n"
                f"**Architecture:** {info.get('architecture', 'Unknown')}\n\n"
                f"**OS:** {info.get('os', 'Unknown')}\n\n"
                f"**Image Size:** {info.get('image_size', 'Unknown')}\n\n"
            )
        elif data_type == 'schema':
            detail_text = (
                f"# Schema Details\n\n"
                f"**Version:** {info['version']}\n\n"
                f"**URL:** {info['url']}\n\n"
            )
        else:
            detail_text = "No data found for selected node."

        detail_text = format_urls_as_markdown(detail_text)
        self.details_display.update(detail_text)

    def quit(self):
        """Exit the application."""
        if self.debug_log_file:
            self.debug_log_file.close()
        self.exit()

def main():
    """Main entry point for the sbommage CLI."""
    # Handle help first, regardless of argument count
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h', 'help']:
        print("Sbommage - Interactive terminal frontend for SBOM files")
        print("")
        print("Usage: sbommage <sbom-file>")
        print("")
        print("Supported SBOM formats:")
        print("  • SPDX")
        print("  • CycloneDX")
        print("  • GitHub dependency graph")
        print("  • Syft")
        print("")
        print("Navigation:")
        print("  • Arrow keys or h/j/k/l - Navigate")
        print("  • Enter - Select item")
        print("  • n - View by Name")
        print("  • t - View by Type")
        print("  • c - View by License")
        print("  • s - View by Supplier")
        print("  • / - Search")
        print("  • q - Quit")
        print("")
        print("Example:")
        print("  sbommage my-app.spdx.json")
        sys.exit(0)
    
    if len(sys.argv) != 2:
        print("Usage: sbommage <sbom-file>")
        print("Use 'sbommage --help' for more information")
        sys.exit(1)
        
    sbom_file = sys.argv[1]
    if not Path(sbom_file).exists():
        print(f"Error: File {sbom_file} does not exist")
        sys.exit(1)
        
    app = Sbommage(sbom_file)
    app.run()

if __name__ == "__main__":
    main()