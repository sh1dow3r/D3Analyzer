import sys
from disk_analyzer import DiskAnalyzer

def main(disk_image):
    print(f"[*] Starting analysis for {disk_image}")
    
    analyzer = DiskAnalyzer(disk_image)
    report = analyzer.analyze_disk()
    
    if report:
        print("\n=== Disk Analysis Report ===")
        print(f"Hostname: {report['basic_info']['hostname']}")
        print(f"OS Version: {report['basic_info']['os_version']}")
        print(f"Users: {report['basic_info']['users']}")
        
        print("\n=== Partitions ===")
        for p in report["partitions"]:
            print(f"Offset: {p['offset']}, Size: {p['size']} bytes, Type: {p['type']}, FS: {p['filesystem']}")
        
        print("\n=== Filesystem Info ===")
        print(f"Filesystem: {report['filesystem_info']['filesystem']}")
        print(f"Volume Serial: {report['filesystem_info']['volume_serial']}")
        print(f"Total Files: {report['filesystem_info']['file_count']}")

        print("\n=== Extracted Artifacts ===")
        print(f"Registry Hives: {report['artifacts']['registry_hives']}")
        print(f"Log Files: {report['artifacts']['log_files']}")

        print("\n[+] Analysis completed successfully!")
    else:
        print("\n[-] Analysis failed.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <disk_image>")
        sys.exit(1)
    
    disk_image_path = sys.argv[1]
    main(disk_image_path)

