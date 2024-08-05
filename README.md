# es
# patch-demo
### env installation
python3 -m venv .venv
. .venv/bin/activate
pip install Flask

### install anthropic (this is running on Vertex AI)
pip install -q --upgrade google-cloud-aiplatform
pip install -U 'anthropic[vertex]'


