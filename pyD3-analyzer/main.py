import os
import json
from dissect.es import ESClient
from dissect.cstruct import Instance
from elasticsearch import Elasticsearch

# Load environment variables
ELASTICSEARCH_HOST = os.getenv("ELASTICSEARCH_HOST", "http://localhost:9200")
ELASTICSEARCH_USERNAME = os.getenv("ELASTICSEARCH_USERNAME", "elastic")
ELASTICSEARCH_PASSWORD = os.getenv("ELASTICSEARCH_PASSWORD", "changeme")
ELASTICSEARCH_INDEX = os.getenv("ELASTICSEARCH_INDEX", "dissect_analysis")

DISK_IMAGES_PATH = os.getenv("DISK_IMAGES_PATH", "/data/disk-images")

# Initialize Elasticsearch client
es = Elasticsearch(
    [ELASTICSEARCH_HOST],
    basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
)

# Ensure index exists
if not es.indices.exists(index=ELASTICSEARCH_INDEX):
    es.indices.create(index=ELASTICSEARCH_INDEX)

def analyze_disk(disk_path):
    """Processes a disk image using Dissect and extracts metadata."""
    try:
        structure = Instance()
        with open(disk_path, "rb") as f:
            data = f.read(512)  # Read first 512 bytes (MBR/PBR)
            parsed_data = structure.unpack("MBR", data)

        parsed_data_dict = {key: str(value) for key, value in parsed_data.items()}

        # Send results to Elasticsearch
        es.index(index=ELASTICSEARCH_INDEX, document={
            "disk_path": disk_path,
            "metadata": parsed_data_dict
        })

        print(f"[+] Analyzed: {disk_path}")
    except Exception as e:
        print(f"[-] Error processing {disk_path}: {e}")

# Iterate over disk images
if os.path.exists(DISK_IMAGES_PATH):
    for image in os.listdir(DISK_IMAGES_PATH):
        image_path = os.path.join(DISK_IMAGES_PATH, image)
        if os.path.isfile(image_path):
            analyze_disk(image_path)

