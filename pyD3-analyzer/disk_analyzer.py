import os
import logging
from datetime import datetime
from dissect.target import Target
from dissect.storage import files

# Configure logging
logging.basicConfig(
    filename="disk_analysis.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

class DiskAnalyzer:
    def __init__(self, disk_path):
        """Initialize the analyzer with a disk image path."""
        self.disk_path = disk_path
        self.target = None

    def load_disk(self):
        """Loads the disk image and initializes the Target object."""
        try:
            self.target = Target.open(self.disk_path)
            logging.info(f"[*] Successfully loaded disk image: {self.disk_path}")
        except Exception as e:
            logging.error(f"[-] Failed to load disk image: {e}")
            return False
        return True

    def get_basic_info(self):
        """Extracts basic system information from the target."""
        if not self.target:
            return None

        info = {
            "disk_path": self.disk_path,
            "analysis_time": datetime.utcnow().isoformat(),
            "hostname": self.target.hostname,
            "os_version": self.target.version,
            "os_type": self.target.os,
            "os_architecture": self.target.arch,
            "users": list(self.target.users())
        }
        logging.info(f"[+] Extracted basic info: {info}")
        return info

    def list_partitions(self):
        """Lists all partitions and their file system types."""
        if not self.target:
            return None

        partitions = []
        for vol in self.target.volumes():
            partitions.append({
                "offset": vol.offset,
                "size": vol.size,
                "type": vol.type,
                "filesystem": vol.fs.__class__.__name__ if vol.fs else "Unknown"
            })
        
        logging.info(f"[+] Found {len(partitions)} partitions.")
        return partitions

    def analyze_filesystem(self, partition_id=0):
        """Extracts key filesystem details (MFT, registry, logs) from a given partition."""
        if not self.target:
            return None
        
        try:
            vol = self.target.volumes()[partition_id]
            fs = vol.fs

            fs_info = {
                "filesystem": fs.__class__.__name__,
                "volume_serial": getattr(fs, 'volume_serial', "Unknown"),
                "file_count": sum(1 for _ in fs.entries())
            }

            logging.info(f"[+] Filesystem analysis completed: {fs_info}")
            return fs_info
        except Exception as e:
            logging.error(f"[-] Filesystem analysis failed: {e}")
            return None

    def extract_artifacts(self):
        """Extracts key forensic artifacts like registry hives and log files."""
        if not self.target:
            return None

        artifacts = {}

        # Extract Windows Registry Hives
        try:
            registry_hives = self.target.registry_hives()
            artifacts["registry_hives"] = list(registry_hives.keys())
            logging.info(f"[+] Extracted registry hives: {artifacts['registry_hives']}")
        except Exception as e:
            logging.warning(f"[-] Failed to extract registry hives: {e}")

        # Extract Log Files
        try:
            log_files = self.target.logs()
            artifacts["log_files"] = list(log_files.keys())
            logging.info(f"[+] Extracted log files: {artifacts['log_files']}")
        except Exception as e:
            logging.warning(f"[-] Failed to extract log files: {e}")

        return artifacts

    def analyze_disk(self):
        """Performs a full disk analysis and returns a comprehensive report."""
        if not self.load_disk():
            return None

        report = {
            "basic_info": self.get_basic_info(),
            "partitions": self.list_partitions(),
            "filesystem_info": self.analyze_filesystem(),
            "artifacts": self.extract_artifacts()
        }

        logging.info(f"[+] Full disk analysis completed for {self.disk_path}")
        return report

