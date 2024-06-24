from flask import Flask, jsonify, request
import os
import vertexai
import socket
import re
from vertexai.preview.generative_models import GenerativeModel, Part
from google.cloud import storage
from flask_cors import CORS, cross_origin

PROJECT_ID = 'ai-sandbox-company-34'

GCS_BUCKET_LOCATION = "us-east1"
GCS_BUCKET_NAME = "patch-demo-data-folder"
GCS_BUCKET_URI = f"gs://{GCS_BUCKET_NAME}"


client = storage.Client()
bucket = storage.Bucket(client, GCS_BUCKET_NAME)
app = Flask(__name__)
cors = CORS(app)
app.config['CORS_HEADERS'] = 'Content-Type'

if bucket.exists()==False:
    # Create a Cloud Storage Bucket
    print(f"\n{GCS_BUCKET_NAME} not exists. \n")
else:    
    print(f"\n{GCS_BUCKET_NAME} folder already exists. Contents:\n")
    
    
# Define CVE Object    
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
    ''' 
    Find the object by cve_id and add the new version
    '''
    for obj in cve_objects:
        if obj.cve_id == cve_id:
            obj.add_version(new_version)
            return True
    return False

def gemini_pro(full_prompt, responseType):
    model = GenerativeModel("gemini-pro")
    responses = model.generate_content(
    full_prompt,
    generation_config={
        "candidate_count": 1,
        "max_output_tokens": 8190,
        "response_mime_type": responseType,
        "temperature": 0,
        "top_p": 1
    },stream=False,)    
    return(responses.text)

def extract_patch_content(patch_files):
    content = ''
    for file in patch_files:
        content = content + file.download_as_text()
    return content

def get_patch_file_by_cve(cve):
    all_files_in_patch_files_folder = list(bucket.list_blobs(prefix=f'{cve}/patch-files/'))
    patch_files = [blob for blob in all_files_in_patch_files_folder if blob.name.endswith('.patch')]
    print(f'what is patch_files, {patch_files}')
    if len(patch_files) > 1:
        print(f'{cve} has more than 1 patch')
    patch_content = extract_patch_content(patch_files)  
    return patch_content

def extract_codesnippets_from_patch(patch_context):
    full_prompt = """\    
    From this file: 
    ---file start---
    {patch_context}
    ---file end---
    I want to remove the header and description, only keep the code snippets from diff,
    in the remaining part
    then, I want to identify the old lines and new lines for each diff
    should only output an array, which containing objects, each object has 2 propertys
    
    "old lines" property, containing old code snippet, 
    "new lines" property, containing new code snippet,
    
    output the object only
    """    
    formatted_prompt = full_prompt.format(
        patch_context=patch_context
    )
    # return formatted_prompt
    return gemini_pro(formatted_prompt, "application/json")

def extract_function_name_prompt(steps):
    full_prompt = """\    
    From this code snippet: 
    ---file start---
    {steps}
    ---file end---
    
    which function gets modified?
    
    output the function name
    """    
    formatted_prompt = full_prompt.format(
        steps=steps
    )
    # return formatted_prompt
    return gemini_pro(formatted_prompt, "text/plain")  

def generate_patched_file_prompt(target_file, diff, function_name):
    full_prompt = """\    
    You are an regex agent, you can replace old code with new code.
    You only do necessary changes when replace old code with new code.
    
    Now, I have this diff:
    
    ---diff start---
    {diff}
    ---diff end---
    
    in this target_file
    ---target_file start---
    {target_file}
    ---target_file end---
    
    modify the target_file according to diff, inside {function_name} replace the old code with new code
    add a trailing brief comment wherever you modified
    
    output the full file in text/plain format
    """   
    formatted_prompt = full_prompt.format(
        target_file=target_file,
        diff=diff,
        function_name=function_name
    )   
    # full_prompt = f'Use these steps {steps} to modify the file {target_file}, for each line, find the value in the "old" property in the file content, and replace with the content in the "new" property, output the modified file'
    return gemini_pro(formatted_prompt, "text/plain")

@app.route("/cve-objects/")
@cross_origin()
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

@app.route("/extract-code-snippets/")
@cross_origin()
def extract_codesnippets():
    cve = request.args.get('cve_id', default = '', type = str)
    patch_content = get_patch_file_by_cve(cve)
    return jsonify(extract_codesnippets_from_patch(patch_content))

@app.route("/extract-function-name/")
@cross_origin()
def extract_function_name():
    code_snippets = request.args.get('code-snippets', default = '', type = str)
    return jsonify(extract_function_name_prompt(code_snippets))

@app.route("/apply-patch/")
@cross_origin()
def apply_patch():
    cve = request.args.get('cve', default = '', type = str)
    code_snippets = request.args.get('code-snippets', default = '', type = str)
    function_name = request.args.get('function-name', default = '', type = str)
    patch_content = get_patch_file_by_cve(cve)
    return jsonify(generate_patched_file_prompt(patch_content, code_snippets, function_name))


