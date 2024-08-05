from flask import Flask, jsonify, request
import urllib.request
import json
from urllib.parse import unquote
import os
import vertexai
import socket
import re
from vertexai.preview.generative_models import GenerativeModel, Part
from google.cloud import storage
from anthropic import AnthropicVertex
from flask_cors import CORS, cross_origin

PROJECT_ID = 'scantist-ai'

GCS_BUCKET_LOCATION = "asia-southeast1-a"
GCS_BUCKET_NAME = "patch-demo-data"
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

def claude(full_prompt):
    client = AnthropicVertex(region="us-east5", project_id=PROJECT_ID)
    # for 3.5 claude-3-5-sonnet@20240620
    message = client.messages.create(
        model="claude-3-sonnet@20240229"
        system="You are a seasoned software developer, working in a Tech Unicorn.",
        max_tokens=4096,
        temperature=0,
        messages=[
            {
                "role": "user",
                "content": full_prompt,
            },
            {
                "role": "assistant",
                "content": "{",
            }
        ],
    )
    
    return json.loads(message.model_dump_json(indent=2))['content']

def extract_patch_content(patch_files):
    content = ''
    for file in patch_files:
        content = content + file.download_as_text()
    return content

def get_target_file_by_cve_and_version(cve, version_number):
    folder_prefix = f'{cve}/{version_number}/'
    target_file = ""
    for blob in bucket.list_blobs(prefix=folder_prefix, delimiter='/'):
        if blob.name != folder_prefix:  # To avoid printing the folder itself
            target_file = blob.download_as_text()
    return target_file

def get_patch_file_by_cve(cve):
    all_files_in_patch_files_folder = list(bucket.list_blobs(prefix=f'{cve}/patch-files/'))
    patch_files = [blob for blob in all_files_in_patch_files_folder if blob.name.endswith('.diff')]
    print(f'what is patch_files, {patch_files}')
    if len(patch_files) > 1:
        print(f'{cve} has more than 1 patch')
    patch_content = extract_patch_content(patch_files)  
    return patch_content

def is_array(diff_result):
    return isinstance(diff_result, list)

def remove_code_formatting(text):
    parts = text.split('```c', 1)
    if len(parts) > 1:
        text = parts[-1].strip()
    parts = text.rsplit('```', 1)
    if len(parts) > 1:
        text = parts[0].strip()
    return text.strip()

def decode_code_snippets(input_string):
    print('encoded_text', input_string)
        
        # Fix escape sequences
        # Load JSON data
    decoded_json = json.loads(input_string)
    print("decoded json", decoded_json)
    # Regular expression to extract all function_name values
    function_name_regex = r'"function_name":(.*?)\\n'
    old_lines_regex = r'"old_lines":(.*?)\]\\n'
    new_lines_regex = r'"new_lines":(.*?)\],?\\n'

    # Find all matches for function_name
    function_names = re.findall(function_name_regex, str(decoded_json))
    old_lines = re.findall(old_lines_regex, str(decoded_json))
    new_lines = re.findall(new_lines_regex, str(decoded_json))    
    # Print all function names
    decoded_json = []
    for index, function_name in enumerate(function_names):
        decoded_json.append({
            "function_name": function_name,
            "old_lines": old_lines[index],
            "new_lines": new_lines[index]
        })
        print(f"Function Name: {function_name}")
        print(f"Old Lines: {old_lines[index]}")
        print(f"New Lines: {new_lines[index]}")
        
    # decoded_json = json.loads(input_string)
    # for item in decoded_json:
    #     if 'text' in item:
    #         item['text'] = unquote(item['text'])    
    return decoded_json

def convert_to_hunk_obj(data):
    # Parse the JSON string into Python objects
    text_value = data['text'].strip()
    # if first charater is not '{' , then add it to complete the prefilling
    if text_value[0] != '{':
        text_value = '{' + text_value
        
    parsed_data = json.loads(text_value)

    # Extract function_name, old_lines, and new_lines from the parsed data
    function_name = parsed_data['changes'][0]['function_name']
    old_lines = parsed_data['changes'][0]['old_lines']
    new_lines = parsed_data['changes'][0]['new_lines']

    # Remove leading '\n' from each line in old_lines and new_lines
    old_lines = [line.strip() for line in old_lines]
    new_lines = [line.strip() for line in new_lines]

    # Construct the final object
    result = {
        'function_name': function_name,
        'old_lines': old_lines,
        'new_lines': new_lines
    }
    print('result:', result)
    return result

def extract_codesnippets_from_patch(patch_context):
    '''
    Single hunk patch
    '''
    full_prompt = """\    
    From this git diff file: 
    ---file start---
    {patch_context}
    ---file end---
    I want to identify the old lines and new lines for each diff
    should only output an array, which containing objects, each object has 3 propertys
    
    Please provide the following information in JSON format:
    
    each object has following properties:
    
    "function_name" property, the function name of this code snippet, including funciton return type and arguments,
    "old_lines" property, containing removed code snippet, 
    "new_lines" property, containing added code snippet,
    
    and return an array of objects, the key for this array is "changes"
    """    
    formatted_prompt = full_prompt.format(
        patch_context=patch_context
    )
    # return formatted_prompt
    return claude(full_prompt=formatted_prompt) 

def extract_target_function(target_file, function_name):
    '''
    Extract target function from target file
    '''
    full_prompt = """\    
    I have this target file:
    
    ---target file start---
    {target_file}
    ---target file end---
    
    I want to extract the target function: {function_name}
    
    Please extract the function definition code snippets and return an object, in JSON format,
    
    the object should have one property:
    
    "function_definition" the function definition code snippets    
    
    """    
    formatted_prompt = full_prompt.format(
        target_file=target_file,
        function_name=function_name
    )
    result = claude(full_prompt=formatted_prompt)
    text_value = result[0]['text'].strip()
    # if first charater is not '{' , then add it to complete the prefilling
    if text_value[0] != '{':
        text_value = '{' + text_value        
    parsed_data = json.loads(text_value)
    return parsed_data['function_definition']

def generate_patched_function(target_function, old_lines, new_lines):
    full_prompt = """\    
    You are an regex agent, you can replace old code with new code.
    You only do necessary changes when replace old code with new code.
    
    Now, I have this diff:
    
    ---diff start---
    old lines: {old_lines}
    
    new lines: {new_lines}
    ---diff end---
    
    in this target function
    ---target function start---
    {target_function}
    ---target function end---
    
    modify the target function according to diff, replace the old code with new code
    add a trailing brief comment wherever you modified
    
    output the target function after modification and return an object, in JSON format,
    
    the object should have one property:
    
    "modified" the function definition code snippets after modification
    """   
    formatted_prompt = full_prompt.format(
        target_function=target_function,
        old_lines=old_lines,
        new_lines=new_lines
    )   
    # full_prompt = f'Use these steps {steps} to modify the file {target_file}, for each line, find the value in the "old" property in the file content, and replace with the content in the "new" property, output the modified file'
    result = claude(formatted_prompt)
    print('what is the modified result', result)
    text_value = result[0]['text'].strip()
    # if first charater is not '{' , then add it to complete the prefilling
    if text_value[0] != '{':
        text_value = '{' + text_value        
    parsed_data = json.loads(text_value)    
    return parsed_data['modified']    

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
    print('obj_list', obj_list)
    return jsonify(obj_list)

@app.route("/extract-code-snippets/")
@cross_origin()
def extract_codesnippets():
    cve = request.args.get('cve_id', default = '', type = str)
    patch_content = get_patch_file_by_cve(cve)
    return jsonify(extract_codesnippets_from_patch(patch_content))

@app.route("/apply-patch/")
@cross_origin()
def apply_patch():
    cve = request.args.get('cve', default = '', type = str)
    version_number = request.args.get('version-number', default = '', type = str)
    code_snippets = request.args.get('code-snippets', default = '', type = str)
    target_file = get_target_file_by_cve_and_version(cve, version_number)

    code_snippets_array = decode_code_snippets(code_snippets)
    print('original code_snippets_array', code_snippets_array)
    print(f'code_snippets_array', type(code_snippets_array))
    print('total iterations:', len(code_snippets_array))
    modified = target_file
    for item in code_snippets_array:
        print(f'code_snippet: {item}')
        obj = item
        print(f'obj: {obj}')
        # extract target function from target file
        target_function = extract_target_function(modified, obj['function_name'])
        print('target_function', target_function)
        patched_function = generate_patched_function(target_function, obj['old_lines'], obj['new_lines'])
        
        # split by target_function and replace it with the patched_function
        head_and_tail = modified.split(target_function)
        modified = patched_function.join(head_and_tail)
        
        # modified = generate_patched_function(target_file, code_snippets)
    return jsonify({
        'original': target_file,
        # 'modified': remove_code_formatting(modified)
        'modified': modified
    })

@app.route('/upload-target-file/', methods=['POST', 'GET'])
@cross_origin()
def fileUpload():
    if request.method == 'POST':
        file = request.files['file']
        data = request.form
        print('data', data)
        filename = file.filename
        # Create a new blob (file) in the bucket
        blob = bucket.blob(f'{data["cve-id"]}/{data["subfolder"]}/{filename}')
        # Upload the file
        blob.upload_from_file(file)
        return jsonify({"name": filename, "status": "success"})
    else:
        return jsonify({"status": "Upload API GET Request Running"})
    
@app.route('/get-vulnerable-files/', methods=['GET'])    
@cross_origin()
def get_vulnerable_files():
    filenames = []
    if request.method == 'GET':
        cve = request.args.get('cve', default = '', type = str)
        version = request.args.get('version', default = '', type = str)
        all_files_in_patch_files_folder = list(bucket.list_blobs(prefix=f'{cve}/{version}/'))
        filenames = [blob.name for blob in all_files_in_patch_files_folder]
    print('what is all file_in', filenames)
    return jsonify(filenames)
    
    
@app.route('/get-patch-links/', methods=['GET'])
@cross_origin()
def get_current_patches():
    filenames = []
    if request.method == 'GET':
        cve = request.args.get('cve', default = '', type = str)
        all_files_in_patch_files_folder = list(bucket.list_blobs(prefix=f'{cve}/patch-files/'))
        filenames = [os.path.splitext(blob.name)[0] for blob in all_files_in_patch_files_folder if blob.name.endswith('.diff')]
    print('what is all file_in', filenames)
    return jsonify(filenames)
    
@app.route('/submit-patch-links/', methods=['POST', 'GET'])
@cross_origin()
def submit_patches():
    if request.method == 'POST':
        data = request.get_json()
        cve = data["cve-id"]
        patches = data["patches"]
        object_list = list(bucket.list_blobs(prefix=f'{cve}/patch-files/'))
        print('object_list', object_list)
        # Create a new blob (file) in the bucket
        print('hao many patches', patches)
        for patch in patches:
            print('patch: ', patch)
            filename = f"{patch.split('/')[-1]}.diff"
            url = f"{patch}.diff"
            # download the patch file
            with urllib.request.urlopen(url) as f:
                diff_file = f.read().decode('utf-8')
            blob = bucket.blob(f'{data["cve-id"]}/{data["subfolder"]}/{filename}')
            # Upload the diff file content to the blob
            blob.upload_from_string(diff_file, content_type='text/plain')
            print('upload finished')
        all_files_in_patch_files_folder = list(bucket.list_blobs(prefix=f'{cve}/patch-files/'))
        print('all files now', all_files_in_patch_files_folder)
        # patch_files = [blob for blob in all_files_in_patch_files_folder if blob.name.endswith('.diff')]
        # print(f'what is patch_files, {patch_files}')
        """Delete a folder and its contents in a GCS bucket."""
        
        return jsonify({"name": 'okay', "status": "success"})
    else:
        return jsonify({"status": "Upload API GET Request Running"})    

@app.route('/delete-patch-links/', methods=['POST', ''])
@cross_origin()
def delete_patches():
    if request.method == 'POST':
        data = request.get_json()
        filename = data["filename"]
        blob = bucket.blob(f'{data["cve-id"]}/patch-files/{filename}.diff')
                # Delete the blob
        blob.delete()

    return jsonify({"message": f"Blob {filename} deleted from bucket", "status": "success"})

@app.route('/delete-vulnerable-files/', methods=['POST'])
@cross_origin()
def delete_vulnerable_files():
    if request.method == 'POST':
        data = request.get_json()
        version = data["version"]
        filename = data["filename"]
        blob = bucket.blob(f'{data["cve-id"]}/{version}/{filename}')
        blob.delete()

    return jsonify({"message": f"Blob {filename} deleted from bucket", "status": "success"})