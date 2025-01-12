import argparse
import logging
import sys
from datetime import datetime

from dissect.target import Target
from dissect.target.exceptions import FatalError, PluginNotFoundError, TargetError, UnsupportedPluginError
from dissect.target.plugin import find_plugin_functions
from dissect.target.report import ExecutionReport
from dissect.target.tools.utils import process_generic_arguments, find_and_filter_plugins, execute_function_on_target

# Configure logging
logging.basicConfig(
    filename="disk_analysis.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

log = logging.getLogger(__name__)
logging.raiseExceptions = False


class DiskAnalyzer:
    def __init__(self, target_paths):
        """Initialize the analyzer with a list of disk image paths."""
        self.targets = Target.open_all(target_paths)
        self.execution_report = ExecutionReport()
        self.analysis_results = []

    def analyze_basic_info(self, target):
        """Extracts basic system information like hostname, OS, and users."""
        try:
            info = {
                "disk_path": target.path,
                "hostname": target.hostname,
                "os_version": target.version,
                "os_type": target.os,
                "os_architecture": getattr(target, "architecture", "Unknown"),  # ✅ FIXED
                "users": list(target.users())
            }
            log.info(f"[+] Extracted basic info: {info}")
            return info
        except Exception as e:
            log.error(f"[-] Failed to extract basic info: {e}")
            return {}

    def analyze_partitions(self, target):
        """Lists all partitions and their file system types."""
        try:
            partitions = []
            for vol in target.volumes:  # ✅ FIXED
                partitions.append({
                    "offset": vol.offset,
                    "size": vol.size,
                    "type": vol.type,
                    "filesystem": vol.fs.__class__.__name__ if vol.fs else "Unknown"
                })
            log.info(f"[+] Found {len(partitions)} partitions.")
            return partitions
        except Exception as e:
            log.error(f"[-] Failed to extract partitions: {e}")
            return []

    def analyze_plugins(self, target, function_filter="*"):
        """Executes all matching Dissect plugins on the target."""
        try:
            results = {}
            functions, _ = find_plugin_functions(target, function_filter, compatibility=False)
            for func_def in find_and_filter_plugins(target, function_filter):
                try:
                    output_type, result, _ = execute_function_on_target(target, func_def, [])
                    if output_type == "record":
                        results[func_def.name] = result
                except (UnsupportedPluginError, PluginNotFoundError) as e:  # ✅ FIXED
                    log.warning(f"[-] Skipping {func_def.name}: {e}")
            return results
        except Exception as e:
            log.error(f"[-] Failed to execute plugins: {e}")
            return {}

    def run_analysis(self):
        """Runs the full forensic analysis on all loaded disk images."""
        for target in self.targets:
            log.info(f"[*] Analyzing target: {target.path}")

            report = {
                "basic_info": self.analyze_basic_info(target),
                "partitions": self.analyze_partitions(target)
                #"plugins": self.analyze_plugins(target, "*"),
            }

            self.analysis_results.append(report)

        return self.analysis_results


