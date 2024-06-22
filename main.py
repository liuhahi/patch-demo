from flask import Flask, jsonify
import os
import vertexai
import socket
import re
from vertexai.preview.generative_models import GenerativeModel, Part
from google.cloud import storage


PROJECT_ID = 'ai-sandbox-company-34'

GCS_BUCKET_LOCATION = "us-east1"
GCS_BUCKET_NAME = "patch-demo-data-folder"
GCS_BUCKET_URI = f"gs://{GCS_BUCKET_NAME}"


client = storage.Client()
bucket = storage.Bucket(client, GCS_BUCKET_NAME)

if bucket.exists()==False:
    # Create a Cloud Storage Bucket
    print(f"\n{GCS_BUCKET_NAME} not exists. \n")
else:    
    print(f"\n{GCS_BUCKET_NAME} folder already exists. Contents:\n")
    
def list_all_cves():
    bucket = client.bucket(GCS_BUCKET_NAME)    
    blobs = bucket.list_blobs()    
    cve_list = set();
    for blob in blobs:        
        parts = blob.name.split('/')
        cve_list.add(parts[0])
    return cve_list

app = Flask(__name__)

class CVEObject:
    def __init__(self, cve_id, versions):
        self.cve_id = cve_id
        self.versions = set(versions)  # Use a set to avoid duplicate versions

    def __hash__(self):
        return hash(self.cve_id)

    def __eq__(self, other):
        return self.cve_id == other.cve_id

    def to_dict(self):
        return {'cve_id': self.cve_id, 'versions': list(self.versions)}

    def add_version(self, new_version):
        self.versions.add(new_version)

def add_cve_version(cve_objects, cve_id, new_version):
    # Find the object by cve_id and add the new version
    for obj in cve_objects:
        if obj.cve_id == cve_id:
            obj.add_version(new_version)
            return True
    return False

@app.route("/cve-objects/")
def list_all_cve_objects():
    '''
    return a list of CVEObject
    '''
    bucket = client.bucket(GCS_BUCKET_NAME)    
    blobs = bucket.list_blobs()    
    cve_list = set();
    object_list = set();
    for blob in blobs:        
        parts = blob.name.split('/')
        # folder structure CVE-xxxx-xxxx/Version/
        cve_id = parts[0]
        version_number = parts[1]
        if version_number == 'patch-files' or version_number == '':
            continue
        if cve_id not in cve_list:
            cve_list.add(parts[0])
            object_list.add(CVEObject(cve_id, [version_number]))            
        else:
            add_cve_version(object_list, cve_id, version_number)     
    obj_list = [obj.to_dict() for obj in object_list]
    return jsonify(obj_list)

