| Command | Quick definition |
| --- | --- |
| `python3 recover.py` | Run recovery with the default captures, SambaTu wordlist and GPU. |
| `python3 recover.py --check` | Check the tools and run a synthetic recovery without processing your captures. |
| `python3 recover.py --status` | Show saved progress for resumable transformed-wordlist attempts. |
| `python3 recover.py --ssid` | Generate candidates from each captured network's own SSID. |
| `python3 recover.py --ssid-rules` | Apply the full SSID transformation profile to the default wordlist. |
| `python3 recover.py --ssid-rules light` | Apply the smaller light profile to the default wordlist. |
| `python3 recover.py --ssid-rules light --estimate-only` | Estimate the light profile's workload without starting recovery. |
| `python3 recover.py --rules rules/basic.json` | Apply the selected JSON mutation catalog to the default wordlist. |
| `python3 recover.py --wordlist PATH/TO/WORDLIST.txt` | Run the batch using a different wordlist. |
| `python3 recover.py --preview-ssid "Minha Rede"` | Preview generated candidates for fictional SSID text without processing captures. |
| `python3 recover.py --preview-ssid "Minha Rede" --preview-limit 12` | Limit the SSID preview to 12 candidates. |
| `python3 recover.py --handshakes PATH --wordlist FILE --output DIR` | Run recovery with custom capture, wordlist and output paths. |
| `python3 recover.py --retry-unusable` | Recheck captures previously recorded as having no usable handshake. |
| `python3 recover.py --ssid-rules light --restart-incomplete` | Back up matching checkpoints and restart incomplete transformed-wordlist attempts. |
| `python3 recover.py --device-types 1` | Run recovery with the OpenCL CPU instead of the default GPU. |
| `node frontend/start.mjs` | Start the local results viewer at `http://127.0.0.1:3000`. |
| `./scripts/check` | Run the required fast repository checks. |
